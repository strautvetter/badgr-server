import io
import datetime
import urllib.request
import urllib.parse
import urllib.error
import base64
import base58
from hashlib import sha256

import dateutil
import re
import uuid
from collections import OrderedDict

import cachemodel
import os
from allauth.account.adapter import get_adapter
from django.apps import apps
from django.conf import settings
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.urls import reverse
from django.db import models, transaction
from django.db.models import ProtectedError
from json import loads as json_loads
from json import dumps as json_dumps

from jsonfield import JSONField
from openbadges_bakery import bake
from django.utils import timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from pyld import jsonld

import badgrlog
from entity.models import BaseVersionedEntity
from issuer.managers import BadgeInstanceManager, IssuerManager, BadgeClassManager, BadgeInstanceEvidenceManager
from mainsite.managers import SlugOrJsonIdCacheModelManager
from mainsite.mixins import HashUploadedImage, ResizeUploadedImage, ScrubUploadedSvgImage, PngImagePreview
from mainsite.models import BadgrApp, EmailBlacklist
from mainsite import blacklist
from mainsite.utils import OriginSetting, generate_entity_uri, get_name
from .utils import (add_obi_version_ifneeded, CURRENT_OBI_VERSION, assertion_is_v3, generate_rebaked_filename,
                    generate_sha256_hashstring, get_obi_context, parse_original_datetime, UNVERSIONED_BAKED_VERSION,
                    generate_private_key_pem)

from geopy.geocoders import Nominatim
AUTH_USER_MODEL = getattr(settings, 'AUTH_USER_MODEL', 'auth.User')

RECIPIENT_TYPE_EMAIL = 'email'
RECIPIENT_TYPE_ID = 'openBadgeId'
RECIPIENT_TYPE_TELEPHONE = 'telephone'
RECIPIENT_TYPE_URL = 'url'

logger = badgrlog.BadgrLogger()


class BaseAuditedModel(cachemodel.CacheModel):
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    created_by = models.ForeignKey('badgeuser.BadgeUser', blank=True, null=True, related_name="+",
                                   on_delete=models.SET_NULL)
    updated_at = models.DateTimeField(auto_now=True, db_index=True)
    updated_by = models.ForeignKey('badgeuser.BadgeUser', blank=True, null=True, related_name="+",
                                   on_delete=models.SET_NULL)

    class Meta:
        abstract = True

    @property
    def cached_creator(self):
        from badgeuser.models import BadgeUser
        return BadgeUser.cached.get(id=self.created_by_id)


class BaseAuditedModelDeletedWithUser(cachemodel.CacheModel):
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    created_by = models.ForeignKey('badgeuser.BadgeUser', blank=True, null=True, related_name="+",
                                   on_delete=models.CASCADE)
    updated_at = models.DateTimeField(auto_now=True, db_index=True)
    updated_by = models.ForeignKey('badgeuser.BadgeUser', blank=True, null=True, related_name="+",
                                   on_delete=models.CASCADE)

    class Meta:
        abstract = True

    @property
    def cached_creator(self):
        from badgeuser.models import BadgeUser
        return BadgeUser.cached.get(id=self.created_by_id)


class OriginalJsonMixin(models.Model):
    original_json = models.TextField(blank=True, null=True, default=None)

    class Meta:
        abstract = True

    def get_original_json(self):
        if self.original_json:
            try:
                return json_loads(self.original_json)
            except (TypeError, ValueError):
                pass

    def get_filtered_json(self, excluded_fields=()):
        original = self.get_original_json()
        if original is not None:
            return {key: original[key] for key in [k for k in list(original.keys()) if k not in excluded_fields]}


class BaseOpenBadgeObjectModel(OriginalJsonMixin, cachemodel.CacheModel):
    source = models.CharField(max_length=254, default='local')
    source_url = models.CharField(max_length=254, blank=True, null=True, default=None, unique=True)

    class Meta:
        abstract = True

    def get_extensions_manager(self):
        raise NotImplementedError()

    def __hash__(self):
        return hash((self.source, self.source_url))

    def __eq__(self, other):
        UNUSABLE_DEFAULT = uuid.uuid4()

        comparable_properties = getattr(self, 'COMPARABLE_PROPERTIES', None)
        if comparable_properties is None:
            return super(BaseOpenBadgeObjectModel, self).__eq__(other)

        for prop in self.COMPARABLE_PROPERTIES:
            if getattr(self, prop) != getattr(other, prop, UNUSABLE_DEFAULT):
                return False
        return True

    @cachemodel.cached_method(auto_publish=True)
    def cached_extensions(self):
        return self.get_extensions_manager().all()

    @property
    def extension_items(self):
        return {e.name: json_loads(e.original_json) for e in self.cached_extensions()}

    @extension_items.setter
    def extension_items(self, value):
        if value is None:
            value = {}
        touched_idx = []

        with transaction.atomic():
            if not self.pk and value:
                self.save()

            # add new
            for ext_name, ext in list(value.items()):
                ext_json = json_dumps(ext)
                ext, ext_created = self.get_extensions_manager().get_or_create(name=ext_name, defaults=dict(
                    original_json=ext_json
                ))
                if not ext_created:
                    ext.original_json = ext_json
                    ext.save()
                touched_idx.append(ext.pk)

            # remove old
            for extension in self.cached_extensions():
                if extension.pk not in touched_idx:
                    extension.delete()


class BaseOpenBadgeExtension(cachemodel.CacheModel):
    name = models.CharField(max_length=254)
    original_json = models.TextField(blank=True, null=True, default=None)

    def __str__(self):
        return self.name

    class Meta:
        abstract = True


class Issuer(ResizeUploadedImage,
             ScrubUploadedSvgImage,
             PngImagePreview,
             BaseAuditedModel,
             BaseVersionedEntity,
             BaseOpenBadgeObjectModel):
    entity_class_name = 'Issuer'
    COMPARABLE_PROPERTIES = ('badgrapp_id', 'description', 'email',
                            'entity_id', 'entity_version', 'name',
                            'pk', 'updated_at', 'url')

    staff = models.ManyToManyField(AUTH_USER_MODEL, through='IssuerStaff')

    # slug has been deprecated for now, but preserve existing values
    slug = models.CharField(max_length=255, db_index=True, blank=True, null=True, default=None)
    # slug = AutoSlugField(max_length=255, populate_from='name', unique=True, blank=False, editable=True)

    badgrapp = models.ForeignKey('mainsite.BadgrApp', blank=True, null=True, default=None, on_delete=models.SET_NULL)

    name = models.CharField(max_length=1024)
    image = models.FileField(upload_to='uploads/issuers', blank=True, null=True)
    description = models.TextField(blank=True, null=True, default=None)
    url = models.CharField(max_length=254, blank=True, null=True, default=None)
    email = models.CharField(max_length=254, blank=True, null=True, default=None)
    old_json = JSONField()

    verified = models.BooleanField(null=False, default=False)


    objects = IssuerManager()
    cached = SlugOrJsonIdCacheModelManager(slug_kwarg_name='entity_id', slug_field_name='entity_id')

    category = models.CharField(max_length=255, null=False, default='n/a')

    # address fields
    street = models.CharField(max_length=255, null=True, blank=True)
    streetnumber = models.CharField(max_length=255, null=True, blank=True)
    zip = models.CharField(max_length=255, null=True, blank=True)
    city = models.CharField(max_length=255, null=True, blank=True)
    country = models.CharField(max_length=255, null=True, blank=True)

    intendedUseVerified = models.BooleanField(null=False, default=False)

    lat = models.FloatField(null=True, blank=True)
    lon = models.FloatField(null=True, blank=True)

    private_key = models.CharField(max_length=512, blank=True, null=True, default=generate_private_key_pem)

    def publish(self, publish_staff=True, *args, **kwargs):
        fields_cache = self._state.fields_cache  # stash the fields cache to avoid publishing related objects here
        self._state.fields_cache = dict()

        super(Issuer, self).publish(*args, **kwargs)
        if publish_staff:
            for member in self.cached_issuerstaff():
                member.cached_user.publish()

        self._state.fields_cache = fields_cache  # restore the fields cache

    def has_nonrevoked_assertions(self):
        return self.badgeinstance_set.filter(revoked=False).exists()

    def delete(self, *args, **kwargs):
        if self.has_nonrevoked_assertions():
            raise ProtectedError("Issuer can not be deleted because it has previously issued badges.", self)

        # remove any unused badgeclasses owned by issuer
        for bc in self.cached_badgeclasses():
            bc.delete()

        staff = self.cached_issuerstaff()
        # remove membership records
        for membership in staff:
            membership.delete(publish_issuer=False)
        ret = super(Issuer, self).delete(*args, **kwargs)



        if apps.is_installed('badgebook'):
            # badgebook shim
            try:
                from badgebook.models import LmsCourseInfo
                # update LmsCourseInfo's that were using this issuer as the default_issuer
                for course_info in LmsCourseInfo.objects.filter(default_issuer=self):
                    course_info.default_issuer = None
                    course_info.save()
            except ImportError:
                pass

        return ret

    def save(self, *args, **kwargs):
        original_verified = None
        if not self.pk:
            self.notify_admins(self)
        # geocoding if address in model changed
        else:
            original_object = Issuer.objects.get(pk=self.pk)
            original_verified = original_object.verified

            if (self.street != original_object.street
                    or self.streetnumber != original_object.streetnumber
                    or self.city != original_object.city
                    or self.zip != original_object.zip
                    or self.country != original_object.country):
                addr_string = ((self.street if self.street is not None else '') + " "
                + (str(self.streetnumber) if self.streetnumber is not None else '') + " "
                + (str(self.zip) if self.zip is not None else '') + " "
                + (str(self.city) if self.city is not None else '') + " Deutschland")
                nom = Nominatim(user_agent="OpenEducationalBadges")
                geoloc = nom.geocode(addr_string)
                if geoloc:
                    self.lon = geoloc.longitude
                    self.lat = geoloc.latitude

        ensureOwner = kwargs.pop('ensureOwner', True)
        ret = super(Issuer, self).save(*args, **kwargs)

        # notify the owner of the Issuer on verification
        if original_verified == False and self.verified:
            self.notify_issuer_owner(self)
        # The user who created the issuer should always be an owner
        if ensureOwner:
            self.ensure_owner()

        return ret

    def ensure_owner(self):
        """Makes sure the issuer has a staff with role owner

        An issuer staff relation is either created with role owner
        (if none existed), or updated to contain the role
        ROLE_OWNER.
        Earlier this also made sure that the creator was the owner;
        since this doesn't seem to be required anymore though,
        this now merely makes sure that both a creator and an
        owner exist (if possible)
        """

        # If there exists both a creator and an owner, there's nothing to do
        # (I think; it's not clearly specified)
        if self.staff.filter(issuerstaff__role=IssuerStaff.ROLE_OWNER) and \
            self.created_by:
            return

        # If there already is an IssuerStaff entry I have to edit it
        if self.created_by and \
              IssuerStaff.objects.filter(user=self.created_by, issuer=self).exists():
            issuerStaff = IssuerStaff.objects.get(user=self.created_by, issuer=self)
            issuerStaff.role = IssuerStaff.ROLE_OWNER
            issuerStaff.save()
            return

        # If I don't have a creator, this means they were deleted.
        # If there are other users associated, I can chose the one with the highest privileges
        if not self.created_by:
            owners = self.staff.filter(issuerstaff__role=IssuerStaff.ROLE_OWNER)
            editors = self.staff.filter(issuerstaff__role=IssuerStaff.ROLE_EDITOR)
            staff = self.staff.filter(issuerstaff__role=IssuerStaff.ROLE_STAFF)
            if owners.exists():
                self.created_by = owners.first()
                self.save(ensureOwner = False)
                # Is already owner
                return
            elif editors.exists():
                self.created_by = editors.first()
                self.save(ensureOwner = False)
            elif staff.exists():
                self.created_by = staff.first()
                self.save(ensureOwner = False)
            else:
                # With no other staff, there's nothing we can do. So we unverify the issuer
                self.verified = False
                self.save(ensureOwner = False)
                return
            # The new "creator" should also be the owner
            issuerStaff = IssuerStaff.objects.get(user=self.created_by, issuer=self)
            issuerStaff.role = IssuerStaff.ROLE_OWNER
            issuerStaff.save()
            return

        # The last remaining case is that the created_by user still exists, but got removed as owner
        # In this case there must be no owner assigned currently, so we chose a new owner
        editors = self.staff.filter(issuerstaff__role=IssuerStaff.ROLE_EDITOR)
        staff = self.staff.filter(issuerstaff__role=IssuerStaff.ROLE_STAFF)
        if editors.exists():
            new_owner = editors.first()
        elif staff.exists():
            new_owner = staff.first()
        else:
            # If there is no other user, we (re-)assign the creator as owner.
            # This is also the case for the initial creation
            new_owner = IssuerStaff.objects.create(issuer=self, user=self.created_by, role=IssuerStaff.ROLE_OWNER)
            return
        new_owner.role = IssuerStaff.ROLE_OWNER
        new_owner.save()

    def new_contact_email(self):
        # If this method is called, this may mean that the owner got deleted.
        # This implicates that we have to take measures to ensure a new owner is applied.
        self.ensure_owner()
        # We set the contact email to the first email of the first owner we find
        owners = self.staff.filter(issuerstaff__role=IssuerStaff.ROLE_OWNER)
        if not owners.exists():
            # Without an owner, there's nothing we can do
            return
        owner = owners.first()
        self.email = owner.primary_email
        self.save()


    def get_absolute_url(self):
        return reverse('issuer_json', kwargs={'entity_id': self.entity_id})

    @property
    def public_url(self):
        return OriginSetting.HTTP + self.get_absolute_url()

    def image_url(self, public=False):
        if bool(self.image):
            if public:
                return OriginSetting.HTTP + reverse('issuer_image', kwargs={'entity_id': self.entity_id})
            if getattr(settings, 'MEDIA_URL').startswith('http'):
                return default_storage.url(self.image.name)
            else:
                return getattr(settings, 'HTTP_ORIGIN') + default_storage.url(self.image.name)
        else:
            return None

    @property
    def jsonld_id(self):
        if self.source_url:
            return self.source_url
        return OriginSetting.HTTP + self.get_absolute_url()

    @property
    def editors(self):
        return self.staff.filter(issuerstaff__role__in=(IssuerStaff.ROLE_EDITOR, IssuerStaff.ROLE_OWNER))

    @property
    def owners(self):
        return self.staff.filter(issuerstaff__role=IssuerStaff.ROLE_OWNER)

    @cachemodel.cached_method(auto_publish=True)
    def cached_issuerstaff(self):
        return IssuerStaff.objects.filter(issuer=self)

    @property
    def staff_items(self):
        return self.cached_issuerstaff()

    @staff_items.setter
    def staff_items(self, value):
        """
        Update this issuers IssuerStaff from a list of IssuerStaffSerializerV2 data
        """
        existing_staff_idx = {s.cached_user: s for s in self.staff_items}
        new_staff_idx = {s['cached_user']: s for s in value}

        with transaction.atomic():
            # add missing staff records
            for staff_data in value:
                if staff_data['cached_user'] not in existing_staff_idx:
                    staff_record, created = IssuerStaff.cached.get_or_create(
                        issuer=self,
                        user=staff_data['cached_user'],
                        defaults={
                            'role': staff_data['role']
                        })
                    if not created:
                        staff_record.role = staff_data['role']
                        staff_record.save()

            # remove old staff records -- but never remove the only OWNER role
            for staff_record in self.staff_items:
                if staff_record.cached_user not in new_staff_idx:
                    if staff_record.role != IssuerStaff.ROLE_OWNER or len(self.owners) > 1:
                        staff_record.delete()

    def get_extensions_manager(self):
        return self.issuerextension_set

    @cachemodel.cached_method(auto_publish=True)
    def cached_editors(self):
        UserModel = get_user_model()
        return UserModel.objects.filter(issuerstaff__issuer=self, issuerstaff__role=IssuerStaff.ROLE_EDITOR)

    @cachemodel.cached_method(auto_publish=True)
    def cached_badgeclasses(self):
        return self.badgeclasses.all().order_by("created_at")

    @cachemodel.cached_method(auto_publish=True)
    def cached_learningpaths(self):
        return self.learningpaths.all().order_by("created_at")

    @property
    def image_preview(self):
        return self.image

    def get_json(self, obi_version=CURRENT_OBI_VERSION, include_extra=True, use_canonical_id=False):
        obi_version, context_iri = get_obi_context(obi_version)

        id = self.jsonld_id if use_canonical_id else add_obi_version_ifneeded(self.jsonld_id, obi_version)

        json = OrderedDict({'@context': context_iri})
        json.update(OrderedDict(
            type='Issuer',
            id=id,
            name=self.name,
            url=self.url,
            email=self.email,
            description=self.description,
            category=self.category,
            slug=self.entity_id))

        image_url = self.image_url(public=True)
        json['image'] = image_url
        if self.original_json:
            image_info = self.get_original_json().get('image', None)
            if isinstance(image_info, dict):
                json['image'] = image_info
                json['image']['id'] = image_url

        # source url
        if self.source_url:
            if obi_version == '1_1':
                json["source_url"] = self.source_url
                json["hosted_url"] = OriginSetting.HTTP + self.get_absolute_url()
            elif obi_version == '2_0':
                json["sourceUrl"] = self.source_url
                json["hostedUrl"] = OriginSetting.HTTP + self.get_absolute_url()

        # extensions
        if len(self.cached_extensions()) > 0:
            for extension in self.cached_extensions():
                json[extension.name] = json_loads(extension.original_json)

        # pass through imported json
        if include_extra:
            extra = self.get_filtered_json()
            if extra is not None:
                for k, v in list(extra.items()):
                    if k not in json:
                        json[k] = v


        # add verificationMethod
        if obi_version == '3_0':

            private_key = serialization.load_pem_private_key(
                self.private_key.encode(),
                settings.SECRET_KEY.encode()
            )
            public_key = private_key.public_key()

            # for multicodec
            ed01_prefix = b'\xed\x01'

            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            public_key_base58 = base58.b58encode(
                ed01_prefix + public_key_bytes
            ).decode()

            # z prefix for multibase 58
            public_key_multibase = f'z{public_key_base58}'

            json['verificationMethod'] = OrderedDict({
                "id": f"{id}#key-0",
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-rdf-2022",
                "controller": id,
                "publicKeyMultibase": public_key_multibase
            })

        return json

    @property
    def json(self):
        return self.get_json()

    def get_filtered_json(self, excluded_fields=('@context', 'id', 'type', 'name',
            'url', 'description', 'image', 'email')):
        return super(Issuer, self).get_filtered_json(excluded_fields=excluded_fields)

    @property
    def cached_badgrapp(self):
        id = self.badgrapp_id if self.badgrapp_id else None
        return BadgrApp.objects.get_by_id_or_default(badgrapp_id=id)

    def notify_admins(self, badgr_app=None, renotify=False):
        """
        Sends an email notification to the badge recipient.
        """

        if badgr_app is None:
            badgr_app = self.cached_issuer.cached_badgrapp
        if badgr_app is None:
            badgr_app = BadgrApp.objects.get_current(None)

        UserModel = get_user_model()
        users = UserModel.objects.filter(is_staff=True)

        email_context = {
            # 'badge_name': self.badgeclass.name,
            # 'badge_id': self.entity_id,
            # 'badge_description': self.badgeclass.description,
            # 'help_email': getattr(settings, 'HELP_EMAIL', 'help@badgr.io'),
            'issuer_name': re.sub(r'[^\w\s]+', '', self.name, 0, re.I),
            'users': users,
            # 'issuer_email': self.issuer.email,
            # 'issuer_detail': self.issuer.public_url,
            # 'issuer_image_url': issuer_image_url,
            # 'badge_instance_url': self.public_url,
            # 'image_url': self.public_url + '/image?type=png',
            # 'download_url': self.public_url + "?action=download",
            'site_name': "Open Educational Badges"
            # 'badgr_app': badgr_app
        }

        # Notify admin whether issuer was automatically verified or needs to be verified manually
        if self.verified:
            template_name = 'issuer/email/notify_admins_issuer_verified'
        else:
            template_name = 'issuer/email/notify_admins'

        adapter = get_adapter()
        for user in users:
            adapter.send_mail(template_name, user.email, context=email_context)

    # Notify Issuer owner when issuer gets verified
    def notify_issuer_owner(self, badgr_app=None, renotify=False):
        """
        Sends an email notification to the Issuer owner.
        """
        if badgr_app is None:
            badgr_app = self.cached_issuer.cached_badgrapp
        if badgr_app is None:
            badgr_app = BadgrApp.objects.get_current(None)

        try:
            email_context = {
                # removes all special characters from the issuer name (keeps whitespces, digits and alphabetical characters )
                'issuer_name': re.sub(r'[^\w\s]+', '', self.name, 0, re.I),
                'issuer_url': self.url,
                'issuer_email': self.email,
                'site_name': re.sub(r'@', '', badgr_app.name),
                'badgr_app': badgr_app
            }
        except KeyError as e:
            # A property isn't stored right in json
            raise e

        template_name = 'issuer/email/notify_issuer_verified'

        adapter = get_adapter()
        adapter.send_mail(template_name, self.email, context=email_context)

class IssuerStaff(cachemodel.CacheModel):
    ROLE_OWNER = 'owner'
    ROLE_EDITOR = 'editor'
    ROLE_STAFF = 'staff'
    ROLE_CHOICES = (
        (ROLE_OWNER, 'Owner'),
        (ROLE_EDITOR, 'Editor'),
        (ROLE_STAFF, 'Staff'),
    )
    issuer = models.ForeignKey(Issuer,
                               on_delete=models.CASCADE)
    user = models.ForeignKey(AUTH_USER_MODEL,
                             on_delete=models.CASCADE)
    role = models.CharField(max_length=254, choices=ROLE_CHOICES, default=ROLE_STAFF)

    class Meta:
        unique_together = ('issuer', 'user')

    def publish(self):
        super(IssuerStaff, self).publish()
        self.issuer.publish(publish_staff=False)
        self.user.publish()

    def delete(self, *args, **kwargs):
        publish_issuer = kwargs.pop('publish_issuer', True)
        new_contact = self.is_staff_contact()
        super(IssuerStaff, self).delete()
        if publish_issuer:
            self.issuer.publish(publish_staff=False)
        self.user.publish()
        # Note that this delete method is not called if the user is deleted,
        # since the cascade is done on the database level. That means that this logic
        # *also* has to be contained in the delete method of the user
        if (new_contact):
            self.issuer.new_contact_email()

    def is_staff_contact(self) -> bool:
        # Get verified emails of associated user
        user_emails = self.user.verified_emails
        # Get email of issuer
        issuer_email = self.issuer.email
        # Check if overlap exists
        if (issuer_email == None):
            return False
        return any(user_email.email == issuer_email for user_email in user_emails)

    @property
    def cached_user(self):
        from badgeuser.models import BadgeUser
        return BadgeUser.cached.get(pk=self.user_id)

    @property
    def cached_issuer(self):
        return Issuer.cached.get(pk=self.issuer_id)


def get_user_or_none(recipient_id, recipient_type):
    from badgeuser.models import UserRecipientIdentifier, CachedEmailAddress
    user = None
    if recipient_type == 'email':
        verified_email = CachedEmailAddress.objects.filter(verified=True, email=recipient_id).first()
        if verified_email:
            user = verified_email.user
    else:
        verified_recipient_id = UserRecipientIdentifier.objects.filter(verified=True,
                                                                       identifier=recipient_id).first()
        if verified_recipient_id:
            user = verified_recipient_id.user

    return user


class BadgeClass(ResizeUploadedImage,
                 ScrubUploadedSvgImage,
                 HashUploadedImage,
                 PngImagePreview,
                 BaseAuditedModel,
                 BaseVersionedEntity,
                 BaseOpenBadgeObjectModel):
    entity_class_name = 'BadgeClass'
    COMPARABLE_PROPERTIES = ('criteria_text', 'criteria_url', 'description', 'entity_id', 'entity_version',
                             'expires_amount', 'expires_duration', 'name', 'pk', 'slug', 'updated_at',)

    EXPIRES_DURATION_DAYS = 'days'
    EXPIRES_DURATION_WEEKS = 'weeks'
    EXPIRES_DURATION_MONTHS = 'months'
    EXPIRES_DURATION_YEARS = 'years'
    EXPIRES_DURATION_CHOICES = (
        (EXPIRES_DURATION_DAYS, 'Days'),
        (EXPIRES_DURATION_WEEKS, 'Weeks'),
        (EXPIRES_DURATION_MONTHS, 'Months'),
        (EXPIRES_DURATION_YEARS, 'Years'),
    )

    issuer = models.ForeignKey(Issuer, blank=False, null=False, on_delete=models.CASCADE, related_name="badgeclasses")

    # slug has been deprecated for now, but preserve existing values
    slug = models.CharField(max_length=255, db_index=True, blank=True, null=True, default=None)
    # slug = AutoSlugField(max_length=255, populate_from='name', unique=True, blank=False, editable=True)

    name = models.CharField(max_length=255)
    image = models.FileField(upload_to='uploads/badges', blank=True)
    imageFrame = models.BooleanField(default=True)
    image_preview = models.FileField(upload_to='uploads/badges', blank=True, null=True)
    description = models.TextField(blank=True, null=True, default=None)

    criteria_url = models.CharField(max_length=254, blank=True, null=True, default=None)
    criteria_text = models.TextField(blank=True, null=True)

    expires_amount = models.IntegerField(blank=True, null=True, default=None)
    expires_duration = models.CharField(max_length=254, choices=EXPIRES_DURATION_CHOICES,
                                        blank=True, null=True, default=None)

    old_json = JSONField()

    objects = BadgeClassManager()
    cached = SlugOrJsonIdCacheModelManager(slug_kwarg_name='entity_id', slug_field_name='entity_id')

    class Meta:
        verbose_name_plural = "Badge classes"

    def save(self, *args, **kwargs):
        self.clean()
        return super().save(*args, **kwargs)

    def clean(self):
        # Check if the issuer for this badge is verified, otherwise throw an error
        if not self.issuer.verified:
            raise ValidationError(
                "Only verified issuers can create / update badges",
                code="invalid"
            )

    def publish(self):
        fields_cache = self._state.fields_cache  # stash the fields cache to avoid publishing related objects here
        self._state.fields_cache = dict()
        super(BadgeClass, self).publish()
        self.issuer.publish(publish_staff=False)
        if self.created_by:
            self.created_by.publish()

        self._state.fields_cache = fields_cache  # restore the fields cache

    def delete(self, *args, **kwargs):
        # if there are some assertions that have not expired
        if self.badgeinstances.filter(revoked=False).filter(
                models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=timezone.now())).exists():
            raise ProtectedError("BadgeClass may only be deleted if all BadgeInstances have been revoked.", self)

        issuer = self.issuer
        super(BadgeClass, self).delete(*args, **kwargs)
        issuer.publish(publish_staff=False)

    def schedule_image_update_task(self):
        from issuer.tasks import rebake_all_assertions_for_badge_class
        batch_size = getattr(settings, 'BADGE_ASSERTION_AUTO_REBAKE_BATCH_SIZE', 100)
        rebake_all_assertions_for_badge_class.delay(self.pk, limit=batch_size, replay=True)

    def get_absolute_url(self):
        return reverse('badgeclass_json', kwargs={'entity_id': self.entity_id})

    @property
    def public_url(self):
        return OriginSetting.HTTP + self.get_absolute_url()

    @property
    def jsonld_id(self):
        if self.source_url:
            return self.source_url
        return OriginSetting.HTTP + self.get_absolute_url()

    @property
    def issuer_jsonld_id(self):
        return self.cached_issuer.jsonld_id

    def get_criteria_url(self):
        if self.criteria_url:
            return self.criteria_url
        return OriginSetting.HTTP + reverse('badgeclass_criteria', kwargs={'entity_id': self.entity_id})

    @property
    def description_nonnull(self):
        return self.description if self.description else ""

    @description_nonnull.setter
    def description_nonnull(self, value):
        self.description = value

    @property
    def owners(self):
        return self.cached_issuer.owners

    @property
    def cached_issuer(self):
        return Issuer.cached.get(pk=self.issuer_id)

    def has_nonrevoked_assertions(self):
        return self.badgeinstances.filter(revoked=False).exists()

    """
    Included for legacy purposes. It is inefficient to routinely call this for
    badge classes with large numbers of assertions.
    """
    @property
    def v1_api_recipient_count(self):
        return self.badgeinstances.filter(revoked=False).count()

    @cachemodel.cached_method(auto_publish=True)
    def cached_alignments(self):
        return self.badgeclassalignment_set.all()

    @property
    def alignment_items(self):
        return self.cached_alignments()

    @alignment_items.setter
    def alignment_items(self, value):
        if value is None:
            value = []
        keys = ['target_name', 'target_url', 'target_description', 'target_framework', 'target_code']

        def _identity(align):
            """build a unique identity from alignment json"""
            return "&".join("{}={}".format(k, align.get(k, None)) for k in keys)

        def _obj_identity(alignment):
            """build a unique identity from alignment json"""
            return "&".join("{}={}".format(k, getattr(alignment, k)) for k in keys)

        existing_idx = {_obj_identity(a): a for a in self.alignment_items}
        new_idx = {_identity(a): a for a in value}

        with transaction.atomic():
            # HACKY, but force a save to self otherwise we can't create related objects here
            if not self.pk:
                self.save()

            # add missing records
            for align in value:
                if _identity(align) not in existing_idx:
                    alignment = self.badgeclassalignment_set.create(**align)

            # remove old records
            for alignment in self.alignment_items:
                if _obj_identity(alignment) not in new_idx:
                    alignment.delete()

    @cachemodel.cached_method(auto_publish=True)
    def cached_tags(self):
        return self.badgeclasstag_set.all()

    @property
    def tag_items(self):
        return self.cached_tags()

    @tag_items.setter
    def tag_items(self, value):
        if value is None:
            value = []
        existing_idx = [t.name for t in self.tag_items]
        new_idx = value

        with transaction.atomic():
            if not self.pk:
                self.save()

            # add missing
            for t in value:
                if t not in existing_idx:
                    tag = self.badgeclasstag_set.create(name=t)

            # remove old
            for tag in self.tag_items:
                if tag.name not in new_idx:
                    tag.delete()

    def get_extensions_manager(self):
        return self.badgeclassextension_set

    def issue(self, recipient_id=None, evidence=None, narrative=None, notify=False,
            created_by=None, allow_uppercase=False, badgr_app=None,
            recipient_type=RECIPIENT_TYPE_EMAIL, **kwargs):
        return BadgeInstance.objects.create(
            badgeclass=self, recipient_identifier=recipient_id, recipient_type=recipient_type,
            narrative=narrative, evidence=evidence,
            notify=notify, created_by=created_by, allow_uppercase=allow_uppercase,
            badgr_app=badgr_app,
            user=get_user_or_none(recipient_id, recipient_type),
            **kwargs
        )

    def image_url(self, public=False):
        if public:
            return OriginSetting.HTTP + reverse('badgeclass_image', kwargs={'entity_id': self.entity_id})

        if getattr(settings, 'MEDIA_URL').startswith('http'):
            return default_storage.url(self.image.name)
        else:
            return getattr(settings, 'HTTP_ORIGIN') + default_storage.url(self.image.name)

    def get_json(self, obi_version=CURRENT_OBI_VERSION, include_extra=True, use_canonical_id=False,  include_orgImg=False):
        obi_version, context_iri = get_obi_context(obi_version)
        json = OrderedDict({'@context': context_iri})
        json.update(OrderedDict(
            type='BadgeClass',
            id=self.jsonld_id if use_canonical_id else add_obi_version_ifneeded(self.jsonld_id, obi_version),
            name=self.name,
            description=self.description_nonnull,
            issuer=self.cached_issuer.jsonld_id if use_canonical_id else add_obi_version_ifneeded(
                self.cached_issuer.jsonld_id, obi_version),
        ))

        # image
        if self.image:
            image_url = self.image_url(public=True)
            json['image'] = image_url
            if self.original_json:
                original_json = self.get_original_json()
                if original_json is not None:
                    image_info = original_json.get('image', None)
                    if isinstance(image_info, dict):
                        json['image'] = image_info
                        json['image']['id'] = image_url

        # criteria
        if obi_version == '1_1':
            json["criteria"] = self.get_criteria_url()
        elif obi_version == '2_0':
            json["criteria"] = {}
            if self.criteria_url:
                json['criteria']['id'] = self.criteria_url
            if self.criteria_text:
                json['criteria']['narrative'] = self.criteria_text

        # source_url
        if self.source_url:
            if obi_version == '1_1':
                json["source_url"] = self.source_url
                json["hosted_url"] = OriginSetting.HTTP + self.get_absolute_url()
            elif obi_version == '2_0':
                json["sourceUrl"] = self.source_url
                json["hostedUrl"] = OriginSetting.HTTP + self.get_absolute_url()

        # alignment / tags
        if obi_version == '2_0':
            json['alignment'] = [a.get_json(obi_version=obi_version) for a in self.cached_alignments()]
            json['tags'] = list(t.name for t in self.cached_tags())

        # required
        json['extensions:CompetencyExtension'] = []

        # extensions
        if len(self.cached_extensions()) > 0:
            for extension in self.cached_extensions():
                if not include_orgImg and extension.name != 'extensions:OrgImageExtension':
                    json[extension.name] = json_loads(extension.original_json)

        # pass through imported json
        if include_extra:
            extra = self.get_filtered_json()
            if extra is not None:
                for k, v in list(extra.items()):
                    if k not in json:
                        json[k] = v

        return json

    @property
    def json(self):
        return self.get_json()

    def get_filtered_json(self, excluded_fields=('@context', 'id', 'type', 'name',
            'description', 'image', 'criteria', 'issuer')):
        return super(BadgeClass, self).get_filtered_json(excluded_fields=excluded_fields)

    @property
    def cached_badgrapp(self):
        return self.cached_issuer.cached_badgrapp

    def generate_expires_at(self, issued_on=None):
        if not self.expires_duration or not self.expires_amount:
            return None

        if issued_on is None:
            issued_on = timezone.now()

        duration_kwargs = dict()
        duration_kwargs[self.expires_duration] = self.expires_amount
        return issued_on + dateutil.relativedelta.relativedelta(**duration_kwargs)


class BadgeInstance(BaseAuditedModel,
                    BaseVersionedEntity,
                    BaseOpenBadgeObjectModel):
    entity_class_name = 'Assertion'
    COMPARABLE_PROPERTIES = ('badgeclass_id', 'entity_id', 'entity_version', 'issued_on', 'pk', 'narrative',
                             'recipient_identifier', 'recipient_type', 'revoked', 'revocation_reason', 'updated_at',)

    issued_on = models.DateTimeField(blank=False, null=False, default=timezone.now)

    badgeclass = models.ForeignKey(BadgeClass, blank=False, null=False,
                                   on_delete=models.CASCADE, related_name='badgeinstances')
    issuer = models.ForeignKey(Issuer, blank=False, null=False,
                               on_delete=models.CASCADE)
    user = models.ForeignKey('badgeuser.BadgeUser', blank=True, null=True, on_delete=models.SET_NULL)

    RECIPIENT_TYPE_CHOICES = (
        (RECIPIENT_TYPE_EMAIL, 'email'),
        (RECIPIENT_TYPE_ID, 'openBadgeId'),
        (RECIPIENT_TYPE_TELEPHONE, 'telephone'),
        (RECIPIENT_TYPE_URL, 'url'),
    )
    recipient_identifier = models.CharField(max_length=768, blank=False, null=False, db_index=True)
    recipient_type = models.CharField(max_length=255, choices=RECIPIENT_TYPE_CHOICES,
                                      default=RECIPIENT_TYPE_EMAIL, blank=False, null=False)

    image = models.FileField(upload_to='uploads/badges', blank=True)

    # slug has been deprecated for now, but preserve existing values
    slug = models.CharField(max_length=255, db_index=True, blank=True, null=True, default=None)

    revoked = models.BooleanField(default=False, db_index=True)
    revocation_reason = models.CharField(max_length=255, blank=True, null=True, default=None)

    expires_at = models.DateTimeField(blank=True, null=True, default=None)

    ACCEPTANCE_UNACCEPTED = 'Unaccepted'
    ACCEPTANCE_ACCEPTED = 'Accepted'
    ACCEPTANCE_REJECTED = 'Rejected'
    ACCEPTANCE_CHOICES = (
        (ACCEPTANCE_UNACCEPTED, 'Unaccepted'),
        (ACCEPTANCE_ACCEPTED, 'Accepted'),
        (ACCEPTANCE_REJECTED, 'Rejected'),
    )
    acceptance = models.CharField(max_length=254, choices=ACCEPTANCE_CHOICES, default=ACCEPTANCE_UNACCEPTED)

    hashed = models.BooleanField(default=True)
    salt = models.CharField(max_length=254, blank=True, null=True, default=None)

    narrative = models.TextField(blank=True, null=True, default=None)

    old_json = JSONField()

    objects = BadgeInstanceManager()
    cached = SlugOrJsonIdCacheModelManager(slug_kwarg_name='entity_id', slug_field_name='entity_id')

    class Meta:
        index_together = (
                ('recipient_identifier', 'badgeclass', 'revoked'),
        )

    @property
    def extended_json(self):
        extended_json = self.json
        extended_json['badge'] = self.badgeclass.json
        extended_json['badge']['issuer'] = self.issuer.json

        return extended_json

    def image_url(self, public=False):
        if public:
            return OriginSetting.HTTP + reverse('badgeinstance_image', kwargs={'entity_id': self.entity_id})
        if getattr(settings, 'MEDIA_URL').startswith('http'):
            return default_storage.url(self.image.name)
        else:
            return getattr(settings, 'HTTP_ORIGIN') + default_storage.url(self.image.name)

    def get_share_url(self, include_identifier=False):
        url = self.share_url
        if include_identifier:
            url = '%s?identity__%s=%s' % (url, self.recipient_type, urllib.parse.quote(self.recipient_identifier))
        return url

    @property
    def share_url(self):
        return self.public_url
        # return OriginSetting.HTTP+reverse('backpack_shared_assertion', kwargs={'share_hash': self.entity_id})

    @property
    def cached_issuer(self):
        return Issuer.cached.get(pk=self.issuer_id)

    @property
    def cached_badgeclass(self):
        return BadgeClass.cached.get(pk=self.badgeclass_id)

    def get_absolute_url(self):
        return reverse('badgeinstance_json', kwargs={'entity_id': self.entity_id})

    @property
    def jsonld_id(self):
        if self.source_url:
            return self.source_url
        return OriginSetting.HTTP + self.get_absolute_url()

    @property
    def badgeclass_jsonld_id(self):
        return self.cached_badgeclass.jsonld_id

    @property
    def issuer_jsonld_id(self):
        return self.cached_issuer.jsonld_id

    @property
    def public_url(self):
        return OriginSetting.HTTP + self.get_absolute_url()

    @property
    def owners(self):
        return self.issuer.owners

    @property
    def pending(self):
        """
            If the associated identifier for this BadgeInstance
            does not exist or is unverified the BadgeInstance is
            considered "pending"
        """
        from badgeuser.models import CachedEmailAddress, UserRecipientIdentifier
        try:
            if self.recipient_type == RECIPIENT_TYPE_EMAIL:
                existing_identifier = CachedEmailAddress.cached.get(email=self.recipient_identifier)
            else:
                existing_identifier = UserRecipientIdentifier.cached.get(identifier=self.recipient_identifier)
        except (UserRecipientIdentifier.DoesNotExist, CachedEmailAddress.DoesNotExist,):
            return False

        if not self.source_url:
            return False

        return not existing_identifier.verified

    def save(self, *args, **kwargs):
        if self.pk is None:
            # First check if recipient is in the blacklist
            if blacklist.api_query_is_in_blacklist(self.recipient_type, self.recipient_identifier):
                logger.event(badgrlog.BlacklistAssertionNotCreatedEvent(self))
                raise ValidationError("You may not award this badge to this recipient.")

            self.salt = uuid.uuid4().hex
            self.created_at = datetime.datetime.now()

            # do this now instead of in AbstractVersionedEntity.save() so we can use it for image name
            if self.entity_id is None:
                self.entity_id = generate_entity_uri()

            if not self.image:
                badgeclass_name, ext = os.path.splitext(self.badgeclass.image.file.name)
                new_image = io.BytesIO()
                bake(image_file=self.cached_badgeclass.image.file,
                     assertion_json_string=json_dumps(self.get_json(obi_version=UNVERSIONED_BAKED_VERSION), indent=2),
                     output_file=new_image)
                self.image.save(name='assertion-{id}{ext}'.format(id=self.entity_id, ext=ext),
                                content=ContentFile(new_image.read()),
                                save=False)

            try:
                from badgeuser.models import CachedEmailAddress
                existing_email = CachedEmailAddress.cached.get(email=self.recipient_identifier)
                if self.recipient_identifier != existing_email.email and \
                        self.recipient_identifier not in [e.email for e in existing_email.cached_variants()]:
                    existing_email.add_variant(self.recipient_identifier)
            except CachedEmailAddress.DoesNotExist:
                pass

        if self.revoked is False:
            self.revocation_reason = None

        super(BadgeInstance, self).save(*args, **kwargs)

    def rebake(self, obi_version=CURRENT_OBI_VERSION, save=True):
        new_image = io.BytesIO()
        bake(
            image_file=self.cached_badgeclass.image.file,
            assertion_json_string=json_dumps(self.get_json(obi_version=obi_version), indent=2),
            output_file=new_image
        )

        new_filename = generate_rebaked_filename(self.image.name, self.cached_badgeclass.image.name)
        new_name = default_storage.save(new_filename, ContentFile(new_image.read()))
        default_storage.delete(self.image.name)
        self.image.name = new_name
        if save:
            self.save()

    def publish(self):
        fields_cache = self._state.fields_cache  # stash the fields cache to avoid publishing related objects here
        self._state.fields_cache = dict()

        super(BadgeInstance, self).publish()
        self.badgeclass.publish()
        if self.recipient_user:
            self.recipient_user.publish()

        # publish all collections this instance was in
        for collection in self.backpackcollection_set.all():
            collection.publish()

        self.publish_by('entity_id', 'revoked')
        self._state.fields_cache = fields_cache  # restore the stashed fields cache

    def delete(self, *args, **kwargs):
        badgeclass = self.badgeclass

        super(BadgeInstance, self).delete(*args, **kwargs)
        badgeclass.publish()
        if self.recipient_user:
            self.recipient_user.publish()
        self.publish_delete('entity_id', 'revoked')

    def revoke(self, revocation_reason):
        if self.revoked:
            raise ValidationError("Assertion is already revoked")

        if not revocation_reason:
            raise ValidationError("revocation_reason is required")

        self.revoked = True
        self.revocation_reason = revocation_reason
        self.image.delete()
        self.save()

    # TODO: Use email related to the new domain, when one is created. Not urgent in this phase.
    def notify_earner(self, badgr_app=None, renotify=False):
        """
        Sends an email notification to the badge recipient.
        """

        competencyExtensions = {}

        if len(self.badgeclass.cached_extensions()) > 0:
            for extension in self.badgeclass.cached_extensions():
                if(extension.name == 'extensions:CompetencyExtension'):
                    competencyExtensions[extension.name] = json_loads(extension.original_json)

        competencies = []

        for competency in competencyExtensions.get('extensions:CompetencyExtension', []):
            competency_entry = {
                'name': competency.get('name'),
                'description': competency.get('description'),
                'framework': competency.get('framework'),
                'framework_identifier': competency.get('framework_identifier'),
                'source': competency.get('source'),
                'studyLoad': competency.get('studyLoad'),
                'skill': competency.get('category')
            }
            competencies.append(competency_entry)

        if self.recipient_type != RECIPIENT_TYPE_EMAIL:
            return

        try:
            EmailBlacklist.objects.get(email=self.recipient_identifier)
        except EmailBlacklist.DoesNotExist:
            # Allow sending, as this email is not blacklisted.
            pass
        else:
            logger.event(badgrlog.BlacklistEarnerNotNotifiedEvent(self))
            return

        if badgr_app is None:
            badgr_app = self.cached_issuer.cached_badgrapp
        if badgr_app is None:
            badgr_app = BadgrApp.objects.get_current(None)

        adapter = get_adapter()

        # get the base url for the badge instance
        httpPrefix = 'https://' if settings.SECURE_SSL_REDIRECT else 'http://'
        base_url = httpPrefix + badgr_app.cors

        pdf_document = adapter.generate_pdf_content(slug =  self.entity_id, base_url = base_url)
        encoded_pdf_document = base64.b64encode(pdf_document).decode('utf-8')
        data_url = f"data:application/pdf;base64,{encoded_pdf_document}"

        try:
            if self.issuer.image:
                issuer_image_url = self.issuer.public_url + '/image'
            else:
                issuer_image_url = None

            first_name = ''
            last_name = ''

            try:
                if self.recipient_type == RECIPIENT_TYPE_EMAIL:
                    name = get_name(self)
            except BadgeUser.DoesNotExist:
                pass

            email_context = {
                'name': name,
                'badge_name': self.badgeclass.name,
                'badge_id': self.entity_id,
                'badge_description': self.badgeclass.description,
                'badge_competencies': competencies,
                'help_email': getattr(settings, 'HELP_EMAIL', 'info@opensenselab.org'),
                'issuer_name': re.sub(r'[^\w\s]+', '', self.issuer.name, 0, re.I),
                'issuer_url': self.issuer.url,
                'issuer_email': self.issuer.email,
                'issuer_detail': self.issuer.public_url,
                'issuer_image_url': issuer_image_url,
                'badge_instance_url': self.public_url,
                'pdf_download': data_url,
                'pdf_document': pdf_document,
                'image_url': self.public_url + '/image?type=png',
                'download_url': self.public_url + "?action=download",
                'site_name': "Open Educational Badges",
                'site_url': badgr_app.signup_redirect,
                'badgr_app': badgr_app
            }
            if badgr_app.cors == 'badgr.io':
                email_context['promote_mobile'] = True
            if renotify:
                email_context['renotify'] = 'Reminder'
        except KeyError as e:
            # A property isn't stored right in json
            raise e

        template_name = 'issuer/email/notify_earner'
        try:
            from badgeuser.models import CachedEmailAddress
            CachedEmailAddress.objects.get(email=self.recipient_identifier, verified=True)
            template_name = 'issuer/email/notify_account_holder'
            email_context['site_url'] = badgr_app.ui_login_redirect
        except CachedEmailAddress.DoesNotExist:
            pass

        adapter.send_mail(template_name, self.recipient_identifier, context=email_context)

    def get_extensions_manager(self):
        return self.badgeinstanceextension_set

    @property
    def recipient_user(self):
        from badgeuser.models import CachedEmailAddress, UserRecipientIdentifier
        try:
            email_address = CachedEmailAddress.cached.get(email=self.recipient_identifier)
            if email_address.verified:
                return email_address.user
        except CachedEmailAddress.DoesNotExist:
            try:
                identifier = UserRecipientIdentifier.cached.get(identifier=self.recipient_identifier)
                if identifier.verified:
                    return identifier.user
            except UserRecipientIdentifier.DoesNotExist:
                pass
            pass
        return None

    def get_json(self, obi_version=CURRENT_OBI_VERSION, expand_badgeclass=False,
            expand_issuer=False, include_extra=True, use_canonical_id=False):

        # don't recreate assertions for imported badges, exception for badgr-ui frontend code
        if self.original_json:
            json = json_loads(self.original_json)
            # FIXME add objects for badgr-ui frontend assertion handling
            if expand_badgeclass:
                json['badge'] = self.cached_badgeclass.get_json(obi_version=obi_version, include_extra=include_extra)

                if expand_issuer:
                    json['badge']['issuer'] = self.cached_issuer.get_json(obi_version=obi_version, include_extra=include_extra)

            return json

        if obi_version == '3_0':
            return self.get_json_3_0(obi_version, expand_badgeclass, expand_issuer, include_extra, use_canonical_id)

        obi_version, context_iri = get_obi_context(obi_version)

        json = OrderedDict([
            ('@context', context_iri),
            ('type', 'Assertion'),
            ('id', add_obi_version_ifneeded(self.jsonld_id, obi_version)),
            ('badge', add_obi_version_ifneeded(self.cached_badgeclass.jsonld_id, obi_version)),
        ])

        image_url = self.image_url(public=True)
        json['image'] = image_url
        if self.original_json:
            image_info = self.get_original_json().get('image', None)
            if isinstance(image_info, dict):
                json['image'] = image_info
                json['image']['id'] = image_url

        if expand_badgeclass:
            json['badge'] = self.cached_badgeclass.get_json(obi_version=obi_version, include_extra=include_extra)
            json['badge']['slug'] = self.cached_badgeclass.entity_id

            if expand_issuer:
                json['badge']['issuer'] = self.cached_issuer.get_json(
                    obi_version=obi_version, include_extra=include_extra)

        if self.revoked:
            return OrderedDict([
                ('@context', context_iri),
                ('type', 'Assertion'),
                ('id', self.jsonld_id if use_canonical_id else add_obi_version_ifneeded(self.jsonld_id, obi_version)),
                ('revoked', self.revoked),
                ('revocationReason', self.revocation_reason if self.revocation_reason else "")
            ])

        if obi_version == '1_1':
            json["uid"] = self.entity_id
            json["verify"] = {
                "url": self.public_url if use_canonical_id else add_obi_version_ifneeded(self.public_url, obi_version),
                "type": "hosted"
            }
        elif obi_version == '2_0':
            json["verification"] = {
                "type": "HostedBadge"
            }

        # source url
        if self.source_url:
            if obi_version == '1_1':
                json["source_url"] = self.source_url
                json["hosted_url"] = OriginSetting.HTTP + self.get_absolute_url()
            elif obi_version == '2_0':
                json["sourceUrl"] = self.source_url
                json["hostedUrl"] = OriginSetting.HTTP + self.get_absolute_url()

        # evidence
        if self.evidence_url:
            if obi_version == '1_1':
                # obi v1 single evidence url
                json['evidence'] = self.evidence_url
            elif obi_version == '2_0':
                # obi v2 multiple evidence
                json['evidence'] = [e.get_json(obi_version) for e in self.cached_evidence()]

        # narrative
        if self.narrative and obi_version == '2_0':
            json['narrative'] = self.narrative

        # issuedOn / expires
        json['issuedOn'] = self.issued_on.isoformat()
        if self.expires_at:
            json['expires'] = self.expires_at.isoformat()

        # recipient
        if self.hashed:
            json['recipient'] = {
                "hashed": True,
                "type": self.recipient_type,
                "identity": generate_sha256_hashstring(self.recipient_identifier, self.salt),
            }
            if self.salt:
                json['recipient']['salt'] = self.salt
        else:
            json['recipient'] = {
                "hashed": False,
                "type": self.recipient_type,
                "identity": self.recipient_identifier
            }

        # extensions
        if len(self.cached_extensions()) > 0:
            for extension in self.cached_extensions():
                json[extension.name] = json_loads(extension.original_json)

        # pass through imported json
        if include_extra:
            extra = self.get_filtered_json()
            if extra is not None:
                for k, v in list(extra.items()):
                    if k not in json:
                        json[k] = v

        return json

    def get_json_3_0(self, obi_version=CURRENT_OBI_VERSION, expand_badgeclass=False,
            expand_issuer=False, include_extra=True, use_canonical_id=False):

        obi_version, context_iri = get_obi_context(obi_version)

        hashed_recipient = generate_sha256_hashstring(self.recipient_identifier, self.salt)

        json = OrderedDict([
            ('@context', context_iri),
            ('type', 'Assertion'),
            ('id', add_obi_version_ifneeded(self.jsonld_id, obi_version)),
            ('type', ["VerifiableCredential", "OpenBadgeCredential"]),
            ('name', self.cached_badgeclass.name),
            ('evidence', [e.get_json(obi_version) for e in self.cached_evidence()]),
            ('issuer', {
                'id': add_obi_version_ifneeded(self.cached_issuer.jsonld_id, obi_version),
                'type': ["Profile"],
                'name': self.cached_issuer.name,
                'url': self.cached_issuer.url,
                'email': self.cached_issuer.email,
            }),
            ('validFrom', self.issued_on.isoformat()),
            ('credentialSubject', {
                'type': ["AchievementSubject"],
                'identifier': [{
                    'type': "IdentityObject",
                    'identityHash': hashed_recipient,
                    'identityType': 'emailAddress',
                    'hashed': True,
                    'salt': self.salt
                }],
                'achievement': {
                    'id': add_obi_version_ifneeded(self.cached_badgeclass.jsonld_id, obi_version),
                    'type': ['Achievement'],
                    'name': self.cached_badgeclass.name,
                    'description': self.cached_badgeclass.description,
                    'achievementType': 'Badge',
                    'criteria': {
                        'narrative': self.narrative or "",
                    },
                    "image": {
                        "id": self.image_url(public=True),
                        "type": "Image"
                    }
                }
            }),
        ])

        if self.expires_at:
            # json['expirationDate'] = self.expires_at.isoformat()
            json['validUntil'] = self.expires_at.isoformat()


        if self.revoked:
            # FIXME: https://www.imsglobal.org/spec/ob/v3p0/cert#verification-and-status
            # id as url to list of revokations?
            # example(?) https://github.com/openwallet-foundation-labs/learner-credential-wallet/issues/656
            json['credentialStatus'] = {
                'id': add_obi_version_ifneeded(self.jsonld_id, obi_version),
                'type': "1EdTechRevocationList"
            }

        # FIXME extensions
        # if len(self.cached_extensions()) > 0:
        #     extension_contexts = [
        #         # "https://purl.imsglobal.org/spec/ob/v3p0/extensions.json"
        #     ]
        #     for extension in self.cached_extensions():
        #         extension_json = json_loads(extension.original_json)
        #         extension_name = extension.name
        #         # if extension_name.find('extensions:') == 0:
        #         #     extension_name = extension_name[11:]

        #         try:
        #             extension_context = extension_json['@context']
        #             if isinstance(extension_context, list):
        #                 extension_contexts += extension_context
        #             else:
        #                 extension_contexts.append(extension_context)

        #             # del extension_json['@context']

        #         except KeyError:
        #             pass

        #         json[extension_name] = extension_json

        #     # unique
        #     extension_contexts = list(set(extension_contexts))
        #     # json['@context'] += extension_contexts


        # TODO link to v2 version? is this correct?
            # json['related'] = [{
            #     'type': [
            #         "Related",
            #         "https://w3id.org/openbadges#BadgeClass"
            #     ],
            #     "id": add_obi_version_ifneeded(self.jsonld_id, '2_0'),
            #     "version": "Open Badges v2p0"
            # }]


        ##### proof / signing #####

        # as RSA JWT, needs rsa private key
            # import jwt
            # private_key = serialization.load_pem_private_key(
            #     self.cached_issuer.private_key.encode(),
            #     settings.SECRET_KEY.encode()
            # )

            # json = {**json, **{
            #     'iss': json['issuer']['id'],            # issuer.id
            #     'jti': json['id'],                      # vc.id
            #     'nbf': self.issued_on.isoformat(),      # validFrom
            #     # 'sub': json['credentialSubject']['id']  # credentialSubject.id
            #     }
            # }

            # if self.expires_at:
            #     json['exp'] = self.expires_at.isoformat()

            # jwk = jwt.algorithms.RSAAlgorithm.to_jwk(key=private_key)
            # private_key_bytes = private_key.private_bytes(
            #     encoding=serialization.Encoding.Raw,
            #     format=serialization.PrivateFormat.Raw,
            #     encryption_algorithm=serialization.NoEncryption()
            # )

            # jwt_token = jwt.encode(json, key=jwk, headers={
            #     'kid': jwk,
            # })
            # json = jwt_token

            # return json


        # load private key
        private_key = serialization.load_pem_private_key(
            self.cached_issuer.private_key.encode(),
            settings.SECRET_KEY.encode()
        )

        # basic proof dict with added @context
        proof = OrderedDict([
            ("@context", "https://www.w3.org/ns/credentials/v2"),
            ("type", "DataIntegrityProof"),
            ("cryptosuite", "eddsa-rdfc-2022"),
            ("created", self.issued_on.isoformat()),
            ("verificationMethod", f'{add_obi_version_ifneeded(self.cached_issuer.jsonld_id, obi_version)}#key-0'),
            ("proofPurpose", "assertionMethod"),
        ])

        # transform https://www.w3.org/TR/vc-di-eddsa/#transformation-eddsa-rdfc-2022
        # FIXME: this is pretty slow
        canonicalized_proof = jsonld.normalize(proof, {'algorithm': 'URDNA2015', 'format': 'application/n-quads'})
        canonicalized_json = jsonld.normalize(json, {'algorithm': 'URDNA2015', 'format': 'application/n-quads'})

        # if settings.DEBUG:
        #     print(canonicalized_proof)
        #     print(canonicalized_json)

        # hash transformed documents, 32bit each
        hashed_proof = sha256(canonicalized_proof.encode()).digest()
        hashed_json = sha256(canonicalized_json.encode()).digest()


        # concat for 64bit hash ans sign
        signature = private_key.sign(hashed_proof + hashed_json)

        # base58 encode with multibase prefix z
        proof['proofValue'] = f"z{base58.b58encode(signature).decode()}"

        # remove proof @context
        del proof['@context']

        # add proof to json
        json['proof'] = [proof]

        # FIXME add badge object for badgr-ui frontend assertion handling, not a valid ob3 vc key
        if expand_badgeclass:
            json['badge'] = self.cached_badgeclass.get_json(obi_version=obi_version, include_extra=include_extra)

            # FIXME add issuer object for badgr-ui frontend assertion handling, not a valid ob3 vc key
            if expand_issuer:
                json['badge']['issuer'] = self.cached_issuer.get_json(obi_version=obi_version, include_extra=include_extra)

        return json

    @property
    def json(self):
        return self.get_json()

    def get_filtered_json(self, excluded_fields=('@context', 'id', 'type', 'uid',
            'recipient', 'badge', 'issuedOn', 'image', 'evidence', 'narrative', 'revoked',
            'revocationReason', 'verify', 'verification')):
        filtered = super(BadgeInstance, self).get_filtered_json(excluded_fields=excluded_fields)
        # Ensure that the expires date string is in the expected ISO-85601 UTC format
        if filtered is not None and filtered.get('expires', None) and not str(filtered.get('expires')).endswith('Z'):
            filtered['expires'] = parse_original_datetime(filtered['expires'])
        return filtered

    @cachemodel.cached_method(auto_publish=True)
    def cached_evidence(self):
        return self.badgeinstanceevidence_set.all()

    @property
    def evidence_url(self):
        """Exists for compliance with ob1.x badges"""
        evidence_list = self.cached_evidence()
        if len(evidence_list) > 1:
            return self.public_url
        if len(evidence_list) == 1 and evidence_list[0].evidence_url:
            return evidence_list[0].evidence_url
        elif len(evidence_list) == 1:
            return self.public_url

    @property
    def evidence_items(self):
        """exists to cajole EvidenceItemSerializer"""
        return self.cached_evidence()

    @evidence_items.setter
    def evidence_items(self, value):
        def _key(narrative, url):
            return '{}-{}'.format(narrative or '', url or '')
        existing_evidence_idx = {_key(e.narrative, e.evidence_url): e for e in self.evidence_items}
        new_evidence_idx = {_key(v.get('narrative', None), v.get('evidence_url', None)): v for v in value}

        with transaction.atomic():
            if not self.pk:
                self.save()

            # add missing
            for evidence_data in value:
                key = _key(evidence_data.get('narrative', None), evidence_data.get('evidence_url', None))
                if key not in existing_evidence_idx:
                    evidence_record, created = BadgeInstanceEvidence.cached.get_or_create(
                        badgeinstance=self,
                        narrative=evidence_data.get('narrative', None),
                        evidence_url=evidence_data.get('evidence_url', None)
                    )

            # remove old
            for evidence_record in self.evidence_items:
                key = _key(evidence_record.narrative or None, evidence_record.evidence_url or None)
                if key not in new_evidence_idx:
                    evidence_record.delete()

    @property
    def cached_badgrapp(self):
        return self.cached_issuer.cached_badgrapp

    def get_baked_image_url(self, obi_version=CURRENT_OBI_VERSION):
        if obi_version == UNVERSIONED_BAKED_VERSION:
            # requested version is the one referenced in assertion.image
            return self.image.url

        try:
            baked_image = BadgeInstanceBakedImage.cached.get(badgeinstance=self, obi_version=obi_version)
        except BadgeInstanceBakedImage.DoesNotExist:
            # rebake
            baked_image = BadgeInstanceBakedImage(badgeinstance=self, obi_version=obi_version)

            json_to_bake = self.get_json(
                obi_version=obi_version,
                expand_issuer=True,
                expand_badgeclass=True,
                include_extra=True
            )
            badgeclass_name, ext = os.path.splitext(self.badgeclass.image.file.name)
            new_image = io.BytesIO()
            bake(image_file=self.cached_badgeclass.image.file,
                 assertion_json_string=json_dumps(json_to_bake, indent=2),
                 output_file=new_image)
            baked_image.image.save(
                name='assertion-{id}-{version}{ext}'.format(id=self.entity_id, ext=ext, version=obi_version),
                content=ContentFile(new_image.read()),
                save=False
            )
            baked_image.save()

        return baked_image.image.url


def _baked_badge_instance_filename_generator(instance, filename):
    return "baked/{version}/{filename}".format(
        version=instance.obi_version,
        filename=filename
    )


class BadgeInstanceBakedImage(cachemodel.CacheModel):
    badgeinstance = models.ForeignKey('issuer.BadgeInstance',
                                      on_delete=models.CASCADE)
    obi_version = models.CharField(max_length=254)
    image = models.FileField(upload_to=_baked_badge_instance_filename_generator, blank=True)

    def publish(self):
        self.publish_by('badgeinstance', 'obi_version')
        return super(BadgeInstanceBakedImage, self).publish()

    def delete(self, *args, **kwargs):
        self.publish_delete('badgeinstance', 'obi_version')
        return super(BadgeInstanceBakedImage, self).delete(*args, **kwargs)


class BadgeInstanceEvidence(OriginalJsonMixin, cachemodel.CacheModel):
    badgeinstance = models.ForeignKey('issuer.BadgeInstance',
                                      on_delete=models.CASCADE)
    evidence_url = models.CharField(max_length=2083, blank=True, null=True, default=None)
    narrative = models.TextField(blank=True, null=True, default=None)

    objects = BadgeInstanceEvidenceManager()

    def publish(self):
        super(BadgeInstanceEvidence, self).publish()
        self.badgeinstance.publish()

    def delete(self, *args, **kwargs):
        badgeinstance = self.badgeinstance
        ret = super(BadgeInstanceEvidence, self).delete(*args, **kwargs)
        badgeinstance.publish()
        return ret

    def get_json(self, obi_version=CURRENT_OBI_VERSION, include_context=False):
        json = OrderedDict()
        if include_context:
            obi_version, context_iri = get_obi_context(obi_version)
            json['@context'] = context_iri

        json['type'] = 'Evidence'
        if self.evidence_url:
            json['id'] = self.evidence_url
        if self.narrative:
            json['narrative'] = self.narrative
        return json


class BadgeClassAlignment(OriginalJsonMixin, cachemodel.CacheModel):
    badgeclass = models.ForeignKey('issuer.BadgeClass',
                                   on_delete=models.CASCADE)
    target_name = models.TextField()
    target_url = models.CharField(max_length=2083)
    target_description = models.TextField(blank=True, null=True, default=None)
    target_framework = models.TextField(blank=True, null=True, default=None)
    target_code = models.TextField(blank=True, null=True, default=None)

    def publish(self):
        super(BadgeClassAlignment, self).publish()
        self.badgeclass.publish()

    def delete(self, *args, **kwargs):
        super(BadgeClassAlignment, self).delete(*args, **kwargs)
        self.badgeclass.publish()

    def get_json(self, obi_version=CURRENT_OBI_VERSION, include_context=False):
        json = OrderedDict()
        if include_context:
            obi_version, context_iri = get_obi_context(obi_version)
            json['@context'] = context_iri

        json['targetName'] = self.target_name
        json['targetUrl'] = self.target_url
        if self.target_description:
            json['targetDescription'] = self.target_description
        if self.target_framework:
            json['targetFramework'] = self.target_framework
        if self.target_code:
            json['targetCode'] = self.target_code

        return json


class BadgeClassTag(cachemodel.CacheModel):
    badgeclass = models.ForeignKey('issuer.BadgeClass',
                                   on_delete=models.CASCADE)
    name = models.CharField(max_length=254, db_index=True)

    def __str__(self):
        return self.name

    def publish(self):
        super(BadgeClassTag, self).publish()
        self.badgeclass.publish()

    def delete(self, *args, **kwargs):
        super(BadgeClassTag, self).delete(*args, **kwargs)
        self.badgeclass.publish()

class LearningPathTag(cachemodel.CacheModel):
    learningPath = models.ForeignKey('issuer.LearningPath',
                                   on_delete=models.CASCADE)
    name = models.CharField(max_length=254, db_index=True)

    def __str__(self):
        return self.name

    def publish(self):
        super(LearningPathTag, self).publish()

    def delete(self, *args, **kwargs):
        super(LearningPathTag, self).delete(*args, **kwargs)


class IssuerExtension(BaseOpenBadgeExtension):
    issuer = models.ForeignKey('issuer.Issuer',
                               on_delete=models.CASCADE)

    def publish(self):
        super(IssuerExtension, self).publish()
        self.issuer.publish(publish_staff=False)

    def delete(self, *args, **kwargs):
        super(IssuerExtension, self).delete(*args, **kwargs)
        self.issuer.publish(publish_staff=False)


class BadgeClassExtension(BaseOpenBadgeExtension):
    badgeclass = models.ForeignKey('issuer.BadgeClass',
                                   on_delete=models.CASCADE)

    def publish(self):
        super(BadgeClassExtension, self).publish()
        self.badgeclass.publish()

    def delete(self, *args, **kwargs):
        super(BadgeClassExtension, self).delete(*args, **kwargs)
        self.badgeclass.publish()


class BadgeInstanceExtension(BaseOpenBadgeExtension):
    badgeinstance = models.ForeignKey('issuer.BadgeInstance',
                                      on_delete=models.CASCADE)

    def publish(self):
        super(BadgeInstanceExtension, self).publish()
        self.badgeinstance.publish()

    def delete(self, *args, **kwargs):
        super(BadgeInstanceExtension, self).delete(*args, **kwargs)
        self.badgeinstance.publish()

class QrCode(BaseVersionedEntity):

    badgeclass = models.ForeignKey(BadgeClass, blank=False, null=False, on_delete=models.CASCADE, related_name='qrcodes')

    issuer = models.ForeignKey(Issuer,
                               on_delete=models.CASCADE)

    title = models.CharField(max_length=254, blank=False, null=False)

    createdBy = models.CharField(max_length=254, blank=False, null=False)

    valid_from = models.DateTimeField(blank=True, null=True, default=None)

    expires_at = models.DateTimeField(blank=True, null=True, default=None)


class RequestedBadge(BaseVersionedEntity):

    badgeclass = models.ForeignKey(BadgeClass, blank=False, null=False,
                                   on_delete=models.CASCADE, related_name='requestedbadges')
    user = models.ForeignKey('badgeuser.BadgeUser', blank=True, null=True, on_delete=models.SET_NULL,)

    qrcode = models.ForeignKey(QrCode, blank=False, null=False, on_delete=models.CASCADE, related_name='requestedbadges')

    firstName = models.CharField(max_length=254, blank=False, null=False)
    lastName = models.CharField(max_length=254, blank=False, null=False)
    email = models.CharField(max_length=254, blank=True, null=True)

    requestedOn = models.DateTimeField(blank=False, null=False, default=timezone.now)

    status = models.CharField(max_length=254, blank=False, null=False, default='Pending')

class LearningPath(BaseVersionedEntity, BaseAuditedModel):
    name = models.CharField(max_length=254, blank=False, null=False)
    description = models.TextField(blank=True, null=True, default=None)
    issuer = models.ForeignKey(Issuer, blank=False, null=False, on_delete=models.CASCADE, related_name='learningpaths')
    participationBadge = models.ForeignKey(BadgeClass, blank=False, null=False, on_delete=models.CASCADE)
    badgrapp = models.ForeignKey('mainsite.BadgrApp', blank=True, null=True, default=None, on_delete=models.SET_NULL)
    slug = models.CharField(max_length=255, db_index=True, blank=True, null=True, default=None)



    @property
    def public_url(self):
        return OriginSetting.HTTP + self.get_absolute_url()

    @property
    def v1_api_participant_count(self):
        return LearningPathParticipant.objects.filter(learning_path=self).count()

    @property
    def cached_badgrapp(self):
        id = self.badgrapp_id if self.badgrapp_id else None
        return BadgrApp.objects.get_by_id_or_default(badgrapp_id=id)

    @property
    def cached_issuer(self):
        return Issuer.cached.get(pk=self.issuer_id)

    @cachemodel.cached_method(auto_publish=True)
    def cached_learningpathbadges(self):
        return self.learningpathbadge_set.all()

    @property
    def learningpath_badges(self):
        return self.cached_learningpathbadges()

    @learningpath_badges.setter
    def learningpath_badges(self, badges_with_order):
        self.learningpathbadge_set.all().delete()

        for badge, order in badges_with_order:
            LearningPathBadge.objects.create(learning_path=self, badge=badge, order=order)

    @cachemodel.cached_method(auto_publish=True)
    def cached_tags(self):
        return self.learningpathtag_set.all()

    @property
    def tag_items(self):
        return self.cached_tags()

    @tag_items.setter
    def tag_items(self, value):
        if value is None:
            value = []
        existing_idx = [t.name for t in self.tag_items]
        new_idx = value

        with transaction.atomic():
            if not self.pk:
                self.save()

            # add missing
            for t in value:
                if t not in existing_idx:
                    tag = self.learningpathtag_set.create(name=t)

            # remove old
            for tag in self.tag_items:
                if tag.name not in new_idx:
                    tag.delete()

    def get_json(self, obi_version=CURRENT_OBI_VERSION,):

        json = OrderedDict({})
        json.update(OrderedDict(
            name=self.name,
            description=self.description,
            slug=self.entity_id,
            issuer_id= self.issuer.entity_id
            ))

        tags = self.learningpathtag_set.all()
        badges = self.learningpathbadge_set.all()
        image = self.participationBadge.image.url

        json['tags'] = list(t.name for t in tags)

        json['badges'] = [
            {
                'badge': badge.badge.get_json(obi_version=obi_version),
                'order': badge.order
            }
            for badge in badges
        ]

        json["image"] = image

        return json

    def get_absolute_url(self):
        return reverse('learningpath_json', kwargs={'entity_id': self.entity_id})

    def user_has_completed(self, recipient_identifier):
        badgeclasses = [lp_badge.badge for lp_badge in self.learningpath_badges]
        badgeinstances = BadgeInstance.objects.filter(recipient_identifier=recipient_identifier, badgeclass__in=badgeclasses, revoked=False)
        completed_badges = list({badgeinstance.badgeclass for badgeinstance in badgeinstances})

        max_progress = self.calculate_progress(badgeclasses)
        user_progress = self.calculate_progress(completed_badges)

        return user_progress >= max_progress

    def user_should_have_badge(self, recipient_identifier):

        if self.user_has_completed(recipient_identifier):
            # check to only award the participationBadge once
            badgeinstances = BadgeInstance.objects.filter(badgeclass=self.participationBadge, recipient_identifier=recipient_identifier, revoked=False)
            return len(badgeinstances) == 0

        return False

    def calculate_progress(self, badgeclasses):
        return sum(
            json_loads(ext.original_json)['StudyLoad']
            for badge in badgeclasses
            for ext in badge.cached_extensions()
            if ext.name == 'extensions:StudyLoadExtension'
        )

class LearningPathBadge(cachemodel.CacheModel):
    learning_path = models.ForeignKey(LearningPath, on_delete=models.CASCADE)
    badge = models.ForeignKey(BadgeClass, on_delete=models.CASCADE)
    order = models.PositiveIntegerField()

    def publish(self):
        super(LearningPathBadge, self).publish()

    def delete(self, *args, **kwargs):
        super(LearningPathBadge, self).delete(*args, **kwargs)

class LearningPathParticipant(BaseVersionedEntity, BaseAuditedModel):
    user = models.ForeignKey('badgeuser.BadgeUser', on_delete=models.CASCADE)
    learning_path = models.ForeignKey(LearningPath, on_delete=models.CASCADE)
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ['user', 'learning_path']

    @property
    def completed_badges(self):
        lp_badges = LearningPathBadge.objects.filter(learning_path=self.learning_path)
        lp_badgeclasses = [lp_badge.badge for lp_badge in lp_badges]
        badgeinstances = self.user.cached_badgeinstances().filter(badgeclass__in=lp_badgeclasses, revoked=False)
        badgeclasses = list({badgeinstance.badgeclass for badgeinstance in badgeinstances})
        return badgeclasses
        # return self.user.earned_badges.filter(learningpath=self.learning_path)

    @property
    def participationBadgeAssertion(self):
        if self.completed_at is not None:
            badgeinstance = self.user.cached_badgeinstances().filter(revoked=False, badgeclass=self.learning_path.participationBadge).first()
            if badgeinstance is not None:
                return badgeinstance
        else:
            return None

    @property
    def cached_user(self):
        from badgeuser.models import BadgeUser
        return BadgeUser.cached.get(pk=self.user_id)

class RequestedLearningPath(BaseVersionedEntity):

    learningpath = models.ForeignKey(LearningPath, blank=False, null=False,
                                   on_delete=models.CASCADE, related_name='requested_learningpath')
    user = models.ForeignKey('badgeuser.BadgeUser', blank=False, null=False, on_delete=models.CASCADE,)

    requestedOn = models.DateTimeField(blank=False, null=False, default=timezone.now)

    status = models.CharField(max_length=254, blank=False, null=False, default='Pending')