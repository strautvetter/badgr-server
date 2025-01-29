from collections import OrderedDict

import datetime

import dateutil.parser
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db.models import Q
from django.db import transaction
from django.http import Http404
from django.utils import timezone
from django.shortcuts import get_object_or_404

from oauthlib.oauth2.rfc6749.tokens import random_token_generator
from rest_framework import status, serializers
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.status import HTTP_404_NOT_FOUND, HTTP_200_OK, HTTP_400_BAD_REQUEST, HTTP_201_CREATED, HTTP_204_NO_CONTENT
from rest_framework.views import APIView


import badgrlog
from entity.api import BaseEntityListView, BaseEntityDetailView, VersionedObjectMixin, BaseEntityView, \
    UncachedPaginatedViewMixin
from entity.serializers import BaseSerializerV2, V2ErrorSerializer
from issuer.models import Issuer, BadgeClass, BadgeInstance, IssuerStaff, LearningPath, LearningPathParticipant, QrCode, RequestedBadge
from issuer.permissions import (MayIssueBadgeClass, MayEditBadgeClass, IsEditor, IsEditorButOwnerForDelete,
                                IsStaff, ApprovedIssuersOnly, BadgrOAuthTokenHasScope,
                                BadgrOAuthTokenHasEntityScope, AuthorizationIsBadgrOAuthToken, MayIssueLearningPath,
                                is_learningpath_editor, is_learningpath_owner, is_learningpath_staff)
from issuer.serializers_v1 import (IssuerSerializerV1, BadgeClassSerializerV1,
                                   BadgeInstanceSerializerV1, LearningPathParticipantSerializerV1, QrCodeSerializerV1, LearningPathSerializerV1, RequestedBadgeSerializer)
from issuer.serializers_v2 import IssuerSerializerV2, BadgeClassSerializerV2, BadgeInstanceSerializerV2, \
    IssuerAccessTokenSerializerV2
from apispec_drf.decorators import apispec_get_operation, apispec_put_operation, \
    apispec_delete_operation, apispec_list_operation, apispec_post_operation
from mainsite.permissions import AuthenticatedWithVerifiedIdentifier, IsServerAdmin
from mainsite.serializers import CursorPaginatedListSerializer
from mainsite.models import AccessTokenProxy
import logging 

logger = badgrlog.BadgrLogger()

class IssuerList(BaseEntityListView):
    """
    Issuer list resource for the authenticated user
    """
    model = Issuer
    v1_serializer_class = IssuerSerializerV1
    v2_serializer_class = IssuerSerializerV2
    permission_classes = [
        IsServerAdmin
        | (AuthenticatedWithVerifiedIdentifier & BadgrOAuthTokenHasScope & ApprovedIssuersOnly)
    ]
    valid_scopes = ["rw:issuer"]

    create_event = badgrlog.IssuerCreatedEvent

    def get_objects(self, request, **kwargs):
        return self.request.user.cached_issuers()

    @apispec_list_operation('Issuer',
        summary="Get a list of Issuers for authenticated user",
        tags=["Issuers"],
    )
    def get(self, request, **kwargs):
        return super(IssuerList, self).get(request, **kwargs)

    @apispec_post_operation('Issuer',
        summary="Create a new Issuer",
        tags=["Issuers"],
    )
    def post(self, request, **kwargs):
        return super(IssuerList, self).post(request, **kwargs)


class IssuerDetail(BaseEntityDetailView):
    model = Issuer
    v1_serializer_class = IssuerSerializerV1
    v2_serializer_class = IssuerSerializerV2
    permission_classes = [
        IsServerAdmin
        | (AuthenticatedWithVerifiedIdentifier & IsEditorButOwnerForDelete & BadgrOAuthTokenHasScope)
        | BadgrOAuthTokenHasEntityScope
    ]
    valid_scopes = ["rw:issuer", "rw:issuer:*", "rw:serverAdmin"]

    @apispec_get_operation('Issuer',
        summary="Get a single Issuer",
        tags=["Issuers"],
    )
    def get(self, request, **kwargs):
        return super(IssuerDetail, self).get(request, **kwargs)

    @apispec_put_operation('Issuer',
       summary="Update a single Issuer",
       tags=["Issuers"],
        )
    def put(self, request, **kwargs):
        return super(IssuerDetail, self).put(request, **kwargs)

    @apispec_delete_operation('Issuer',
        summary="Delete a single Issuer",
        tags=["Issuers"],
    )
    def delete(self, request, **kwargs):
        return super(IssuerDetail, self).delete(request, **kwargs)


class AllBadgeClassesList(UncachedPaginatedViewMixin, BaseEntityListView):
    """
    GET a list of badgeclasses within one issuer context or
    POST to create a new badgeclass within the issuer context
    """
    model = BadgeClass
    permission_classes = [
        IsServerAdmin
        | (AuthenticatedWithVerifiedIdentifier & IsEditor & BadgrOAuthTokenHasScope)
        | BadgrOAuthTokenHasEntityScope
    ]
    v1_serializer_class = BadgeClassSerializerV1
    v2_serializer_class = BadgeClassSerializerV2
    valid_scopes = ["rw:issuer"]

    def get_queryset(self, request, **kwargs):
        if self.get_page_size(request) is None:
            return request.user.cached_badgeclasses()
        return BadgeClass.objects.filter(issuer__staff=request.user).order_by('created_at')

    @apispec_list_operation('BadgeClass',
        summary="Get a list of BadgeClasses for authenticated user",
        tags=["BadgeClasses"],
    )
    def get(self, request, **kwargs):
        return super(AllBadgeClassesList, self).get(request, **kwargs)

    @apispec_post_operation('BadgeClass',
        summary="Create a new BadgeClass",
        tags=["BadgeClasses"],
        parameters=[
            {
                'in': 'query',
                'name': "num",
                'type': "string",
                'description': 'Request pagination of results'
            },
        ]
    )
    def post(self, request, **kwargs):
        return super(AllBadgeClassesList, self).post(request, **kwargs)


class IssuerBadgeClassList(UncachedPaginatedViewMixin, VersionedObjectMixin, BaseEntityListView):
    """
    GET a list of badgeclasses within one issuer context or
    POST to create a new badgeclass within the issuer context
    """
    model = Issuer  # used by get_object()
    permission_classes = [
        IsServerAdmin
        | (AuthenticatedWithVerifiedIdentifier & IsEditor & BadgrOAuthTokenHasScope)
        | BadgrOAuthTokenHasEntityScope
    ]
    v1_serializer_class = BadgeClassSerializerV1
    v2_serializer_class = BadgeClassSerializerV2
    create_event = badgrlog.BadgeClassCreatedEvent
    valid_scopes = ["rw:issuer", "rw:issuer:*"]

    def get_queryset(self, request=None, **kwargs):
        issuer = self.get_object(request, **kwargs)

        if self.get_page_size(request) is None:
            return issuer.cached_badgeclasses()
        return BadgeClass.objects.filter(issuer=issuer)

    def get_context_data(self, **kwargs):
        context = super(IssuerBadgeClassList, self).get_context_data(**kwargs)
        context['issuer'] = self.get_object(self.request, **kwargs)
        return context

    @apispec_list_operation('BadgeClass',
        summary="Get a list of BadgeClasses for a single Issuer",
        description="Authenticated user must have owner, editor, or staff status on the Issuer",
        tags=["Issuers", "BadgeClasses"],
        parameters=[
            {
                'in': 'query',
                'name': "num",
                'type': "string",
                'description': 'Request pagination of results'
            },
        ]
    )
    def get(self, request, **kwargs):
        return super(IssuerBadgeClassList, self).get(request, **kwargs)

    @apispec_post_operation('BadgeClass',
        summary="Create a new BadgeClass associated with an Issuer",
        description="Authenticated user must have owner, editor, or staff status on the Issuer",
        tags=["Issuers", "BadgeClasses"],
    )
    def post(self, request, **kwargs):
        self.get_object(request, **kwargs)  # trigger a has_object_permissions() check
        return super(IssuerBadgeClassList, self).post(request, **kwargs)
    
class IssuerLearningPathList(UncachedPaginatedViewMixin, VersionedObjectMixin, BaseEntityListView):
    """
    GET a list of learningpaths within one issuer context or
    POST to create a new learningpath within the issuer context
    """
    model = Issuer  # used by get_object()
    permission_classes = [
        IsServerAdmin
        | (AuthenticatedWithVerifiedIdentifier & IsEditor & BadgrOAuthTokenHasScope)
        | BadgrOAuthTokenHasEntityScope
    ]
    v1_serializer_class = LearningPathSerializerV1
    valid_scopes = ["rw:issuer", "rw:issuer:*"]

    def get_queryset(self, request=None, **kwargs):
        issuer = self.get_object(request, **kwargs)
        return LearningPath.objects.filter(issuer=issuer)

    def get_context_data(self, **kwargs):
        context = super(IssuerLearningPathList, self).get_context_data(**kwargs)
        context['issuer'] = self.get_object(self.request, **kwargs)
        return context

    @apispec_list_operation('LearningPath',
        summary="Get a list of LearningPaths for a single Issuer",
        description="Authenticated user must have owner, editor, or staff status on the Issuer",
        tags=["Issuers", "LearningPaths"],
        parameters=[
            {
                'in': 'query',
                'name': "num",
                'type': "string",
                'description': 'Request pagination of results'
            },
        ]
    )
    def get(self, request, **kwargs):
        return super(IssuerLearningPathList, self).get(request, **kwargs)

    @apispec_post_operation('LearningPath',
        summary="Create a new LearningPath associated with an Issuer",
        description="Authenticated user must have owner, editor, or staff status on the Issuer",
        tags=["Issuers", "LearningPath"],
    )
    def post(self, request, **kwargs):
        self.get_object(request, **kwargs)  # trigger a has_object_permissions() check
        return super(IssuerLearningPathList, self).post(request, **kwargs)    

class LearningPathParticipantsList(BaseEntityListView):
    """
    GET a list of learning paths within one issuer context or
    POST to create a new learningpath within the issuer context
    """
    model = LearningPathParticipant
    # permission_classes = [
    #     IsServerAdmin
    #     | (AuthenticatedWithVerifiedIdentifier & IsEditor & BadgrOAuthTokenHasScope)
    #     | BadgrOAuthTokenHasEntityScope
    # ]
    v1_serializer_class = LearningPathParticipantSerializerV1
    valid_scopes = ["rw:issuer"]

    def get_queryset(self):
        learningPathSlug = self.kwargs.get('slug')
        learningPath = LearningPath.objects.get(entity_id=learningPathSlug)
        return LearningPathParticipant.objects.filter(learning_path=learningPath)
    
    @apispec_list_operation('LearningPath',
        summary="Get a list of LearningPaths for authenticated user",
        tags=["LearningPaths"],
    )
    def get(self, request, **kwargs):
        learning_path_id = kwargs.get('slug')
        try:
            learning_path = LearningPath.objects.get(entity_id=learning_path_id)
        except LearningPath.DoesNotExist:
            return Response({"error": "Learning Path not found."}, status=status.HTTP_404_NOT_FOUND)

        participants = LearningPathParticipant.objects.filter(learning_path=learning_path)
        serializer = LearningPathParticipantSerializerV1(participants, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class BadgeClassDetail(BaseEntityDetailView):
    """
    GET details on one BadgeClass.
    PUT and DELETE should be restricted to BadgeClasses that haven't been issued yet.
    """
    model = BadgeClass
    permission_classes = [
        IsServerAdmin
        | (AuthenticatedWithVerifiedIdentifier & MayEditBadgeClass & BadgrOAuthTokenHasScope)
        | BadgrOAuthTokenHasEntityScope
    ]
    v1_serializer_class = BadgeClassSerializerV1
    v2_serializer_class = BadgeClassSerializerV2

    valid_scopes = ["rw:issuer", "rw:issuer:*"]

    @apispec_get_operation('BadgeClass',
        summary='Get a single BadgeClass',
        tags=['BadgeClasses'],
    )
    def get(self, request, **kwargs):
        return super(BadgeClassDetail, self).get(request, **kwargs)

    @apispec_delete_operation('BadgeClass',
        summary="Delete a BadgeClass",
        description="Restricted to owners or editors (not staff) of the corresponding Issuer.",
        tags=['BadgeClasses'],
        responses=OrderedDict([
            ("400", {
                'description': "BadgeClass couldn't be deleted. It may have already been issued."
            }),

        ])
    )
    def delete(self, request, **kwargs):
        base_entity = super(BadgeClassDetail, self)
        badge_class = base_entity.get_object(request, **kwargs)

        logger.event(badgrlog.BadgeClassDeletedEvent(badge_class, request.user))

        return base_entity.delete(request, **kwargs)

    @apispec_put_operation('BadgeClass',
        summary='Update an existing BadgeClass.  Previously issued BadgeInstances will NOT be updated',
        tags=['BadgeClasses'],
    )
    def put(self, request, **kwargs):
        return super(BadgeClassDetail, self).put(request, **kwargs)


class BatchAssertionsIssue(VersionedObjectMixin, BaseEntityView):
    model = BadgeClass  # used by .get_object()
    permission_classes = [
        IsServerAdmin
        | (AuthenticatedWithVerifiedIdentifier & MayIssueBadgeClass & BadgrOAuthTokenHasScope)
        | BadgrOAuthTokenHasEntityScope
    ]
    v1_serializer_class = BadgeInstanceSerializerV1
    v2_serializer_class = BadgeInstanceSerializerV2
    valid_scopes = ["rw:issuer", "rw:issuer:*"]

    def get_context_data(self, **kwargs):
        context = super(BatchAssertionsIssue, self).get_context_data(**kwargs)
        context['badgeclass'] = self.get_object(self.request, **kwargs)
        return context

    @apispec_post_operation('Assertion',
        summary='Issue multiple copies of the same BadgeClass to multiple recipients',
        tags=['Assertions'],
        parameters=[
            {
                "in": "body",
                "name": "body",
                "required": True,
                'schema': {
                    "type": "array",
                    'items': {'$ref': '#/definitions/Assertion'}
                },
            }
        ]
    )
    def post(self, request, **kwargs):
        # verify the user has permission to the badgeclass
        badgeclass = self.get_object(request, **kwargs)
        if not self.has_object_permissions(request, badgeclass):
            return Response(status=HTTP_404_NOT_FOUND)

        try:
            create_notification = request.data.get('create_notification', False)
        except AttributeError:
            return Response(status=HTTP_400_BAD_REQUEST)

        # update passed in assertions to include create_notification
        def _include_create_notification(a):
            a['create_notification'] = create_notification
            return a
        assertions = list(map(_include_create_notification, request.data.get('assertions')))

        # save serializers
        context = self.get_context_data(**kwargs)
        serializer_class = self.get_serializer_class()
        serializer = serializer_class(many=True, data=assertions, context=context)
        if not serializer.is_valid(raise_exception=False):
            serializer = V2ErrorSerializer(instance={},
                                           success=False,
                                           description="bad request",
                                           field_errors=serializer._errors,
                                           validation_errors=[])
            return Response(serializer.data, status=status.HTTP_400_BAD_REQUEST)
        new_instances = serializer.save(created_by=request.user)
        for new_instance in new_instances:
            self.log_create(new_instance)

        return Response(serializer.data, status=status.HTTP_201_CREATED)


class BatchAssertionsRevoke(VersionedObjectMixin, BaseEntityView):
    model = BadgeInstance
    permission_classes = [
        IsServerAdmin
        | (AuthenticatedWithVerifiedIdentifier & MayEditBadgeClass & BadgrOAuthTokenHasScope)
        | BadgrOAuthTokenHasEntityScope
    ]
    v2_serializer_class = BadgeInstanceSerializerV2
    valid_scopes = ["rw:issuer", "rw:issuer:*"]

    def get_context_data(self, **kwargs):
        context = super(BatchAssertionsRevoke, self).get_context_data(**kwargs)
        context['badgeclass'] = self.get_object(self.request, **kwargs)
        return context

    def _process_revoke(self, request, revocation):
        response = {
            "revoked": False,
        }

        entity_id = revocation.get("entityId", None)
        revocation_reason = revocation.get("revocationReason", None)

        if entity_id is None:
            return dict(response, reason="entityId is required")

        response["entityId"] = entity_id

        if revocation_reason is None:
            return dict(response, reason="revocationReason is required")

        response["revocationReason"] = revocation_reason

        try:
            assertion = self.get_object(request, entity_id=entity_id)
        except Http404:
            return dict(response, reason="permission denied or object not found")

        try:
            assertion.revoke(revocation_reason)
        except Exception as e:
            return dict(response, reason=str(e))

        return dict(response, revoked=True)

    @apispec_post_operation('Assertion',
        summary='Revoke multiple Assertions',
        tags=['Assertions'],
        parameters=[
            {
                "in": "body",
                "name": "body",
                "required": True,
                'schema': {
                    "type": "array",
                    'items': {'$ref': '#/definitions/Assertion'}
                },
            }
        ]
    )
    def post(self, request, **kwargs):
        result = [
            self._process_revoke(request, revocation)
            for revocation in self.request.data
        ]

        response_data = BaseSerializerV2.response_envelope(result=result, success=True, description="revoked badges")

        return Response(status=HTTP_200_OK, data=response_data)


class BadgeInstanceList(UncachedPaginatedViewMixin, VersionedObjectMixin, BaseEntityListView):
    """
    GET a list of assertions for a single badgeclass
    POST to issue a new assertion
    """
    model = BadgeClass  # used by get_object()
    permission_classes = [
        IsServerAdmin
        | (AuthenticatedWithVerifiedIdentifier & MayIssueBadgeClass & BadgrOAuthTokenHasScope)
        | BadgrOAuthTokenHasEntityScope
    ]
    v1_serializer_class = BadgeInstanceSerializerV1
    v2_serializer_class = BadgeInstanceSerializerV2
    create_event = badgrlog.BadgeInstanceCreatedEvent
    valid_scopes = ["rw:issuer", "rw:issuer:*"]

    def get_queryset(self, request=None, **kwargs):
        badgeclass = self.get_object(request, **kwargs)
        queryset = BadgeInstance.objects.filter(badgeclass=badgeclass)
        recipients = request.query_params.getlist('recipient', None)
        if recipients:
            queryset = queryset.filter(recipient_identifier__in=recipients)
        if request.query_params.get('include_expired', '').lower() not in ['1', 'true']:
            queryset = queryset.filter(
                Q(expires_at__gte=datetime.datetime.now()) | Q(expires_at__isnull=True))
        if request.query_params.get('include_revoked', '').lower() not in ['1', 'true']:
            queryset = queryset.filter(revoked=False)

        return queryset

    def get_context_data(self, **kwargs):
        context = super(BadgeInstanceList, self).get_context_data(**kwargs)
        context['badgeclass'] = self.get_object(self.request, **kwargs)
        return context

    @apispec_list_operation('Assertion',
        summary="Get a list of Assertions for a single BadgeClass",
        tags=['Assertions', 'BadgeClasses'],
        parameters=[
            {
                'in': 'query',
                'name': "recipient",
                'type': "string",
                'description': 'A recipient identifier to filter by'
            },
            {
                'in': 'query',
                'name': "num",
                'type': "string",
                'description': 'Request pagination of results'
            },
            {
                'in': 'query',
                'name': "include_expired",
                'type': "boolean",
                'description': 'Include expired assertions'
            },
            {
                'in': 'query',
                'name': "include_revoked",
                'type': "boolean",
                'description': 'Include revoked assertions'
            }
        ]
    )
    def get(self, request, **kwargs):
        # verify the user has permission to the badgeclass
        self.get_object(request, **kwargs)
        return super(BadgeInstanceList, self).get(request, **kwargs)

    @apispec_post_operation('Assertion',
        summary="Issue an Assertion to a single recipient",
        tags=['Assertions', 'BadgeClasses'],
    )
    def post(self, request, **kwargs):
        # verify the user has permission to the badgeclass
        self.get_object(request, **kwargs)
        return super(BadgeInstanceList, self).post(request, **kwargs)


class IssuerBadgeInstanceList(UncachedPaginatedViewMixin, VersionedObjectMixin, BaseEntityListView):
    """
    Retrieve all assertions within one issuer
    """
    model = Issuer  # used by get_object()
    permission_classes = [
        IsServerAdmin
        | (AuthenticatedWithVerifiedIdentifier & IsStaff & BadgrOAuthTokenHasScope)
        | BadgrOAuthTokenHasEntityScope
    ]
    v1_serializer_class = BadgeInstanceSerializerV1
    v2_serializer_class = BadgeInstanceSerializerV2
    create_event = badgrlog.BadgeInstanceCreatedEvent
    valid_scopes = ["rw:issuer", "rw:issuer:*"]

    def get_queryset(self, request=None, **kwargs):
        issuer = self.get_object(request, **kwargs)
        queryset = BadgeInstance.objects.filter(issuer=issuer)
        recipients = request.query_params.getlist('recipient', None)
        if recipients:
            queryset = queryset.filter(recipient_identifier__in=recipients)
        if request.query_params.get('include_expired', '').lower() not in ['1', 'true']:
            queryset = queryset.filter(
                Q(expires_at__gte=datetime.datetime.now()) | Q(expires_at__isnull=True))
        if request.query_params.get('include_revoked', '').lower() not in ['1', 'true']:
            queryset = queryset.filter(revoked=False)
        return queryset

    @apispec_list_operation('Assertion',
        summary='Get a list of Assertions for a single Issuer',
        tags=['Assertions', 'Issuers'],
        parameters=[
            {
                'in': 'query',
                'name': "recipient",
                'type': "string",
                'description': 'A recipient identifier to filter by'
            },
            {
                'in': 'query',
                'name': "num",
                'type': "string",
                'description': 'Request pagination of results'
            },
            {
                'in': 'query',
                'name': "include_expired",
                'type': "boolean",
                'description': 'Include expired assertions'
            },
            {
                'in': 'query',
                'name': "include_revoked",
                'type': "boolean",
                'description': 'Include revoked assertions'
            },
        ]
    )
    def get(self, request, **kwargs):
        return super(IssuerBadgeInstanceList, self).get(request, **kwargs)

    @apispec_post_operation('Assertion',
        summary="Issue a new Assertion to a recipient",
        tags=['Assertions', 'Issuers']
    )
    def post(self, request, **kwargs):
        kwargs['issuer'] = self.get_object(request, **kwargs)  # trigger a has_object_permissions() check
        return super(IssuerBadgeInstanceList, self).post(request, **kwargs)


class BadgeInstanceDetail(BaseEntityDetailView):
    """
    Endpoints for (GET)ting a single assertion or revoking a badge (DELETE)
    """
    model = BadgeInstance
    permission_classes = [
        IsServerAdmin
        | (AuthenticatedWithVerifiedIdentifier & MayEditBadgeClass & BadgrOAuthTokenHasScope)
        | BadgrOAuthTokenHasEntityScope
    ]
    v1_serializer_class = BadgeInstanceSerializerV1
    v2_serializer_class = BadgeInstanceSerializerV2
    valid_scopes = ["rw:issuer", "rw:issuer:*"]

    @apispec_get_operation('Assertion',
        summary="Get a single Assertion",
        tags=['Assertions']
    )
    def get(self, request, **kwargs):
        return super(BadgeInstanceDetail, self).get(request, **kwargs)

    @apispec_delete_operation('Assertion',
        summary="Revoke an Assertion",
        tags=['Assertions'],
        responses=OrderedDict([
            ('400', {
                'description': "Assertion is already revoked"
            })
        ]),
        parameters=[{
            "in": "body",
            "name": "body",
            "required": True,
            "schema": {
                "type": "object",
                "properties": {
                    "revocation_reason": {
                        "type": "string",
                        "format": "string",
                        'description': "The reason for revoking this assertion",
                        'required': False
                    },
                }
            }
        }]
    )
    def delete(self, request, **kwargs):
        # verify the user has permission to the assertion
        assertion = self.get_object(request, **kwargs)
        if not self.has_object_permissions(request, assertion):
            return Response(status=HTTP_404_NOT_FOUND)

        revocation_reason = request.data.get('revocation_reason', None)
        if not revocation_reason:
            raise ValidationError({'revocation_reason': "This field is required"})

        try:
            assertion.revoke(revocation_reason)
        except DjangoValidationError as e:
            raise ValidationError(e.message)

        serializer = self.get_serializer_class()(assertion, context={'request': request})

        logger.event(badgrlog.BadgeAssertionRevokedEvent(assertion, request.user))
        return Response(status=HTTP_200_OK, data=serializer.data)

    @apispec_put_operation('Assertion',
        summary="Update an Assertion",
        tags=['Assertions'],
    )
    def put(self, request, **kwargs):
        return super(BadgeInstanceDetail, self).put(request, **kwargs)


class IssuerTokensList(BaseEntityListView):
    model = AccessTokenProxy
    permission_classes = (AuthenticatedWithVerifiedIdentifier, BadgrOAuthTokenHasScope, AuthorizationIsBadgrOAuthToken)
    v2_serializer_class = IssuerAccessTokenSerializerV2
    valid_scopes = ["rw:issuer"]

    @apispec_post_operation('AccessToken',
        summary="Retrieve issuer tokens",
        tags=["Issuers"],
    )
    def post(self, request, **kwargs):
        issuer_entityids = request.data.get('issuers', None)
        if not issuer_entityids:
            raise serializers.ValidationError({"issuers": "field is required"})

        issuers = []
        for issuer_entityid in issuer_entityids:
            try:
                issuer = Issuer.cached.get(entity_id=issuer_entityid)
                self.check_object_permissions(request, issuer)
            except Issuer.DoesNotExist:
                raise serializers.ValidationError({"issuers": "unknown issuer"})
            else:
                issuers.append(issuer)

        tokens = []
        expires = timezone.now() + datetime.timedelta(weeks=5200)

        application_user = request.auth.application.user

        for issuer in issuers:
            scope = "rw:issuer:{}".format(issuer.entity_id)

            if application_user:
                # grant application user staff access to issuer if needed
                staff, staff_created = IssuerStaff.cached.get_or_create(
                    issuer=issuer,
                    user=application_user,
                    defaults=dict(
                        role=IssuerStaff.ROLE_STAFF
                    )
                )

            accesstoken, created = AccessTokenProxy.objects.get_or_create(
                user=application_user,
                application=request.auth.application,
                scope=scope,
                defaults=dict(
                    expires=expires,
                    token=random_token_generator(request)
                )
            )
            tokens.append({
                'issuer': issuer.entity_id,
                'token': accesstoken.token,
                'expires': accesstoken.expires,
            })

        serializer = IssuerAccessTokenSerializerV2(data=tokens, many=True, context=dict(
            request=request,
            kwargs=kwargs
        ))
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data)


class PaginatedAssertionsSinceSerializer(CursorPaginatedListSerializer):
    child = BadgeInstanceSerializerV2()

    def __init__(self, *args, **kwargs):
        self.timestamp = timezone.now()  # take timestamp now before SQL query is run in super.__init__
        super(PaginatedAssertionsSinceSerializer, self).__init__(*args, **kwargs)

    def to_representation(self, data):
        representation = super(PaginatedAssertionsSinceSerializer, self).to_representation(data)
        representation['timestamp'] = self.timestamp.isoformat()
        return representation


class AssertionsChangedSince(BaseEntityView):
    permission_classes = (BadgrOAuthTokenHasScope,)
    valid_scopes = ["r:issuer", "rw:issuer", "rw:serverAdmin"]

    def get_queryset(self, request, since=None):
        user = request.user

        # for efficiency, this is updated to no longer return assertions linked to applications
        # this will just fetch assertions for issuers that the user is a staff member for
        expr = Q(issuer__issuerstaff__user=user)

        if since is not None:
            expr &= Q(updated_at__gt=since)

        qs = BadgeInstance.objects.filter(expr).distinct()
        return qs

    def get(self, request, **kwargs):
        since = request.GET.get('since', None)
        if since is not None:
            try:
                since = dateutil.parser.isoparse(since)
            except ValueError:
                err = V2ErrorSerializer(
                    data={}, field_errors={'since': ["must be ISO-8601 format with time zone"]},
                    validation_errors=[])
                err._success = False
                err._description = "bad request"
                err.is_valid(raise_exception=False)
                return Response(err.data, status=HTTP_400_BAD_REQUEST)

        queryset = self.get_queryset(request, since=since)
        context = self.get_context_data(**kwargs)
        serializer = PaginatedAssertionsSinceSerializer(
            queryset=queryset,
            request=request,
            context=context)
        serializer.is_valid()
        return Response(serializer.data)


class PaginatedBadgeClassesSinceSerializer(CursorPaginatedListSerializer):
    child = BadgeClassSerializerV2()

    def __init__(self, *args, **kwargs):
        self.timestamp = timezone.now()  # take timestamp now before SQL query is run in super.__init__
        super(PaginatedBadgeClassesSinceSerializer, self).__init__(*args, **kwargs)

    def to_representation(self, data):
        representation = super(PaginatedBadgeClassesSinceSerializer, self).to_representation(data)
        representation['timestamp'] = self.timestamp.isoformat()
        return representation


class BadgeClassesChangedSince(BaseEntityView):
    permission_classes = (BadgrOAuthTokenHasScope,)
    valid_scopes = ["r:issuer", "rw:issuer", "rw:serverAdmin"]

    def get_queryset(self, request, since=None):
        user = request.user

        expr = Q(issuer__issuerstaff__user=user)

        if since is not None:
            expr &= Q(updated_at__gt=since)

        qs = BadgeClass.objects.filter(expr).distinct()
        return qs

    def get(self, request, **kwargs):
        since = request.GET.get('since', None)
        if since is not None:
            try:
                since = dateutil.parser.isoparse(since)
            except ValueError:
                err = V2ErrorSerializer(
                    data={}, field_errors={'since': ["must be ISO-8601 format with time zone"]},
                    validation_errors=[])
                err._success = False
                err._description = "bad request"
                err.is_valid(raise_exception=False)
                return Response(err.data, status=HTTP_400_BAD_REQUEST)

        queryset = self.get_queryset(request, since=since)
        context = self.get_context_data(**kwargs)
        serializer = PaginatedBadgeClassesSinceSerializer(
            queryset=queryset,
            request=request,
            context=context)
        serializer.is_valid()
        return Response(serializer.data)


class PaginatedIssuersSinceSerializer(CursorPaginatedListSerializer):
    child = IssuerSerializerV2()

    def __init__(self, *args, **kwargs):
        self.timestamp = timezone.now()  # take timestamp now before SQL query is run in super.__init__
        super(PaginatedIssuersSinceSerializer, self).__init__(*args, **kwargs)

    def to_representation(self, data):
        representation = super(PaginatedIssuersSinceSerializer, self).to_representation(data)
        representation['timestamp'] = self.timestamp.isoformat()
        return representation


class IssuersChangedSince(BaseEntityView):
    permission_classes = (BadgrOAuthTokenHasScope,)
    valid_scopes = ["r:issuer", "rw:issuer", "rw:serverAdmin"]

    def get_queryset(self, request, since=None):
        user = request.user

        expr = Q(issuerstaff__user=user)

        if since is not None:
            expr &= Q(updated_at__gt=since)

        qs = Issuer.objects.filter(expr).distinct()
        return qs

    def get(self, request, **kwargs):
        since = request.GET.get('since', None)
        if since is not None:
            try:
                since = dateutil.parser.isoparse(since)
            except ValueError:
                err = V2ErrorSerializer(
                    data={}, field_errors={'since': ["must be ISO-8601 format with time zone"]},
                    validation_errors=[])
                err._success = False
                err._description = "bad request"
                err.is_valid(raise_exception=False)
                return Response(err.data, status=HTTP_400_BAD_REQUEST)

        queryset = self.get_queryset(request, since=since)
        context = self.get_context_data(**kwargs)
        serializer = PaginatedIssuersSinceSerializer(
            queryset=queryset,
            request=request,
            context=context)
        serializer.is_valid()
        return Response(serializer.data)

class QRCodeDetail(BaseEntityView):
    """
    QrCode list resource for the authenticated user
    """
    model = QrCode
    v1_serializer_class = QrCodeSerializerV1
    # v2_serializer_class = IssuerSerializerV2
    permission_classes = (BadgrOAuthTokenHasScope,)
    valid_scopes = ["rw:issuer"]

    def get_objects(self, request, **kwargs):
        badgeSlug = kwargs.get('badgeSlug')
        issuerSlug = kwargs.get('issuerSlug')
        return QrCode.objects.filter(badgeclass__entity_id=badgeSlug, issuer__entity_id=issuerSlug)
    
    def get_object(self, request, **kwargs):
        qr_code_id = kwargs.get('slug')
        return QrCode.objects.get(entity_id=qr_code_id)

    @apispec_list_operation('QrCode',
        summary="Get a list of QrCodes for authenticated user",
        tags=["QrCodes"],
    )
    def get(self, request, **kwargs):
        serializer_class = self.get_serializer_class()

        if 'slug' in kwargs:
            try:
                qr_code = self.get_object(request, **kwargs)
                serializer = serializer_class(qr_code)  
                return Response(serializer.data, status=status.HTTP_200_OK)
            except QrCode.DoesNotExist:
                return Response({"detail": "QR code not found"}, status=status.HTTP_404_NOT_FOUND)
        else:             
            objects = self.get_objects(request, **kwargs)
            serializer = serializer_class(objects, many=True)

            return Response(serializer.data)

    @apispec_post_operation('QrCode',
        summary="Create a new QrCode",
        tags=["QrCodes"],
    )
    def post(self, request, **kwargs):

        serializer_class = self.get_serializer_class()
        serializer = serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        new_instance = serializer.save()
        return Response(serializer.data, status=HTTP_201_CREATED)
    
    @apispec_put_operation('QrCode',
       summary="Update a single QrCode",
       tags=["QrCodes"],
    )

    def put(self, request, **kwargs):
        qr_code = self.get_object(request, **kwargs)
        serializer_class = self.get_serializer_class()
        serializer = serializer_class(qr_code, data=request.data)
        serializer.is_valid(raise_exception=True)
        updated_instance = serializer.save(updated_by=request.user)
        return Response(serializer.data, status=HTTP_200_OK)
    
    @apispec_delete_operation('QrCode',
        summary="Delete an existing QrCode",
        tags=["QrCodes"],
    )
    def delete(self, request, **kwargs):
        qr_code = self.get_object(request, **kwargs)
        qr_code.delete()
        return Response(status=HTTP_204_NO_CONTENT)
    
class BadgeRequestList(BaseEntityListView):
    model = RequestedBadge    
    v1_serializer_class = RequestedBadgeSerializer
    permission_classes = [
        IsServerAdmin
        | (AuthenticatedWithVerifiedIdentifier & BadgrOAuthTokenHasScope & ApprovedIssuersOnly)
    ]
    valid_scopes = ["rw:issuer"]

    @apispec_delete_operation('RequestedBadge',
        summary="Delete multiple badge requests",
        tags=["Requested Badges"],
    )

    def post(self, request, **kwargs):
        try: 
            ids = request.data.get('ids', [])  

            with transaction.atomic():
                    deletion_queryset = RequestedBadge.objects.filter(
                        entity_id__in=ids,
                    )

                    found_ids = set(deletion_queryset.values_list('entity_id', flat=True))
                    missing_ids = set(map(str, ids)) - set(map(str, found_ids))
                    
                    if missing_ids:
                        return Response(
                            {
                                "error": "Some requests not found",
                                "missing_ids": list(missing_ids)
                            },
                            status=HTTP_404_NOT_FOUND
                        )

                    deleted_count = deletion_queryset.delete()[0]

                    return Response({
                        "message": f"Successfully deleted {deleted_count} badge requests",
                        "deleted_count": deleted_count
                    }, status=HTTP_200_OK)

        except DjangoValidationError as e:
            return Response(
                {"error": str(e)},
                status=HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {"error": "An unexpected error occurred"},
                status=HTTP_400_BAD_REQUEST
            )
        

class LearningPathDetail(BaseEntityDetailView):
    model = LearningPath
    v1_serializer_class = LearningPathSerializerV1
    permission_classes = (BadgrOAuthTokenHasScope, MayIssueLearningPath)
    valid_scopes = ["rw:issuer"]

    @apispec_get_operation('LearningPath',
        summary="Get a single LearningPath",
        tags=["Learningpaths"],
    )
    def get(self, request, **kwargs):
        return super(LearningPathDetail, self).get(request, **kwargs)
    
    @apispec_put_operation('LearningPath',
       summary="Update a single LearningPath",
       tags=["LearningPaths"],
        )
    def put(self, request, **kwargs):
        if(not is_learningpath_editor(request.user, self.get_object(request, **kwargs))):
            return Response({"error": "You are not authorized to delete this learning path."}, status=status.HTTP_403_FORBIDDEN)
        return super(LearningPathDetail, self).put(request, **kwargs)
    
    @apispec_delete_operation('LearningPath',
        summary="Delete a single LearningPath",
        tags=["LearningPaths"],
    )
    def delete(self, request, **kwargs):
        if(not is_learningpath_editor(request.user, self.get_object(request, **kwargs))):
            return Response({"error": "You are not authorized to delete this learning path."}, status=status.HTTP_403_FORBIDDEN)
        return super(LearningPathDetail, self).delete(request, **kwargs)

