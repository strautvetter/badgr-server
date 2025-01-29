from django.views.generic.base import RedirectView, TemplateView
from django.conf.urls.static import static
from mainsite.views import badgeRequestsByBadgeClass, downloadQrCode, deleteLpRequest, requestLearningPath, updateLearningPathparticipant, upload, nounproject, aiskills, requestBadge, deleteBadgeRequest, createCaptchaChallenge, participateInLearningPath, getVersion
from mainsite.views import (
    info_view,
    email_unsubscribe,
    AppleAppSiteAssociation,
    error404,
    error500,
)
from mainsite.views import (
    SitewideActionFormView,
    RedirectToUiLogin,
    DocsAuthorizeRedirect,
    LegacyLoginAndObtainAuthToken,
)
from django.apps import apps
from django.conf import settings
from django.conf.urls import include, url
from django.urls import path

from mainsite.admin import badgr_admin
from backpack.badge_connect_api import (
    BadgeConnectManifestView,
    BadgeConnectManifestRedirectView,
)
from mainsite.oauth2_api import (
    AuthorizationApiView,
    TokenView,
    RevokeTokenView,
    AuthCodeExchange,
    RegisterApiView,
    PublicRegisterApiView,
)
from oidc.oidc_views import OidcView

badgr_admin.autodiscover()
# make sure that any view/model/form imports occur AFTER admin.autodiscover


def django2_include(three_tuple_urlconf):
    (urls, app_name, namespace) = three_tuple_urlconf
    return include((urls, app_name), namespace=namespace)


urlpatterns = [
    # Backup URLs in case the server isn't serving these directly
    url(
        r"^favicon\.png[/]?$",
        RedirectView.as_view(
            url="%simages/favicon.png" % settings.STATIC_URL, permanent=True
        ),
    ),
    url(
        r"^favicon\.ico[/]?$",
        RedirectView.as_view(
            url="%simages/favicon.png" % settings.STATIC_URL, permanent=True
        ),
    ),
    url(
        r"^robots\.txt$",
        RedirectView.as_view(url="%srobots.txt" % settings.STATIC_URL, permanent=True),
    ),
    # legacy logo url redirect
    url(
        r"^static/images/header-logo-120.png$",
        RedirectView.as_view(
            url="{}images/logo.png".format(settings.STATIC_URL), permanent=True
        ),
    ),
    # Apple app universal URL endpoint
    url(
        r"^apple-app-site-association",
        AppleAppSiteAssociation.as_view(),
        name="apple-app-site-association",
    ),
    # OAuth2 provider URLs
    url(
        r"^o/authorize/?$", AuthorizationApiView.as_view(), name="oauth2_api_authorize"
    ),
    url(r"^o/token/?$", TokenView.as_view(), name="oauth2_provider_token"),
    url(r"^o/revoke_token/?$", RevokeTokenView.as_view(), name="oauth2_provider_revoke_token"),
    url(r"^o/code/?$", AuthCodeExchange.as_view(), name="oauth2_code_exchange"),
    url(
        r"^o/register/?$",
        RegisterApiView.as_view(),
        kwargs={"version": "rfc7591"},
        name="oauth2_api_register",
    ),
    url(
        r"^o/publicregister/?$",
        PublicRegisterApiView.as_view(),
        kwargs={"version": "rfc7591"},
        name="oauth2_public_api_register",
    ),
    path("o/", include("oauth2_provider.urls", namespace="oauth2_provider")),
    # Badge Connect URLs
    url(
        r"^bcv1/manifest/(?P<domain>[^/]+)$",
        BadgeConnectManifestView.as_view(),
        name="badge_connect_manifest",
    ),
    url(
        r"^\.well-known/badgeconnect.json$",
        BadgeConnectManifestRedirectView.as_view(),
        name="default_bc_manifest_redirect",
    ),
    url(r"^bcv1/", include("backpack.badge_connect_urls"), kwargs={"version": "bcv1"}),
    # Home
    url(r"^$", info_view, name="index"),
    url(
        r"^accounts/login/$", RedirectToUiLogin.as_view(), name="legacy_login_redirect"
    ),
    # Admin URLs
    url(
        r"^staff/sidewide-actions$",
        SitewideActionFormView.as_view(),
        name="badgr_admin_sitewide_actions",
    ),
    url(r"^staff/", django2_include(badgr_admin.urls)),
    # Service health endpoint
    url(r"^health", include("health.urls")),
    # Swagger Docs
    #
    # api docs
    #
    url(
        r"^docs/oauth2/authorize$",
        DocsAuthorizeRedirect.as_view(),
        name="docs_authorize_redirect",
    ),
    url(
        r"^docs/?$", RedirectView.as_view(url="/docs/v2/", permanent=True)
    ),  # default redirect to /v2/
    url(r"^docs/", include("apispec_drf.urls")),
    # JSON-LD Context
    url(r"^json-ld/", include("badgrlog.urls")),
    # unversioned public endpoints
    url(
        r"^unsubscribe/(?P<email_encoded>[^/]+)/(?P<expiration>[^/]+)/(?P<signature>[^/]+)",
        email_unsubscribe,
        name="unsubscribe",
    ),
    url(r"^public/", include("issuer.public_api_urls"), kwargs={"version": "v2"}),
    # legacy share redirects
    url(r"", include("backpack.share_urls")),
    # Legacy Auth Token Endpoint: Deprecated and logged
    url(r"^api-auth/token$", LegacyLoginAndObtainAuthToken.as_view()),
    # Social Auth (oAuth2 and SAML)
    url(r"^account/", include("badgrsocialauth.urls")),
    # v1 API endpoints
    url(r"^v1/user/", include("badgeuser.v1_api_urls"), kwargs={"version": "v1"}),
    url(r"^v1/user/", include("badgrsocialauth.v1_api_urls"), kwargs={"version": "v1"}),
    url(r"^v1/issuer/", include("issuer.v1_api_urls"), kwargs={"version": "v1"}),
    url(r"^v1/earner/", include("backpack.v1_api_urls"), kwargs={"version": "v1"}),
    # v2 API endpoints
    url(r"^v2/", include("issuer.v2_api_urls"), kwargs={"version": "v2"}),
    url(r"^v2/", include("badgeuser.v2_api_urls"), kwargs={"version": "v2"}),
    url(r"^v2/", include("badgrsocialauth.v2_api_urls"), kwargs={"version": "v2"}),
    url(r"^v2/backpack/", include("backpack.v2_api_urls"), kwargs={"version": "v2"}),
    # External Tools
    url(r'^v1/externaltools/', include('externaltools.v1_api_urls'),
        kwargs={'version': 'v1'}),
    url(r'^v2/externaltools/', include('externaltools.v2_api_urls'),
        kwargs={'version': 'v2'}),

    url(r'^upload', upload, name="image_upload"),
    url(r'^nounproject/(?P<searchterm>[^/]+)/(?P<page>[^/]+)$', nounproject,
        name="nounproject"),

    url(r'^aiskills/(?P<searchterm>[^/]+)$', aiskills, name="aiskills"),

    url(r'^request-badge/(?P<qrCodeId>[^/]+)$', requestBadge, name="request-badge"),

    url(r'^request-learningpath/(?P<lpId>[^/]+)$', requestLearningPath, name="request-learningpath"),

    url(r'^deleteLpRequest/(?P<requestId>[^/]+)$', deleteLpRequest, name="delete-lp-request"),


    url(r'^get-server-version', getVersion, name="get-server-version"),

    url(r'^deleteBadgeRequest/(?P<requestId>[^/]+)$', deleteBadgeRequest, name="delete-badge-request"),

    url(r'^download-qrcode/(?P<qrCodeId>[^/]+)/(?P<badgeSlug>[^/]+)$', downloadQrCode, name="download-qrcode"),
  
    url(r'^badgeRequests/(?P<badgeSlug>[^/]+)$', badgeRequestsByBadgeClass, name="badge-requests-by-badgeclass"),


    url(r'^learningpath/(?P<learningPathId>[^/]+)/participate$', participateInLearningPath, name="participate-in-learningpath"),

    url(r'^learningpath/participant/(?P<participantId>[^/]+)$', updateLearningPathparticipant, name="update-learningpath-participant"),




    # meinBildungsraum OIDC connection
    path('oidc/', include('mozilla_django_oidc.urls')),
    url(r'^oidcview/logoutRedirect/', OidcView.oidcLogoutRedirect, name="oidcLogoutRedirect"),

    url(r"^altcha", createCaptchaChallenge, name="create_captcha_challenge"),

    # Prometheus endpoint
    path('', include('django_prometheus.urls')),
]
# add to serve files
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# Test URLs to allow you to see these pages while DEBUG is True
if getattr(settings, "DEBUG_ERRORS", False):
    urlpatterns = [
        url(r"^error/404/$", error404, name="404"),
        url(r"^error/500/$", error500, name="500"),
    ] + urlpatterns

# If DEBUG_MEDIA is set, have django serve anything in MEDIA_ROOT at MEDIA_URL
if getattr(settings, "DEBUG_MEDIA", True):
    from django.views.static import serve as static_serve

    media_url = getattr(settings, "MEDIA_URL", "/media/").lstrip("/")
    urlpatterns = [
        url(
            r"^media/(?P<path>.*)$",
            static_serve,
            {"document_root": settings.MEDIA_ROOT},
        ),
    ] + urlpatterns

# If DEBUG_STATIC is set, have django serve up static files even if DEBUG=False
if getattr(settings, "DEBUG_STATIC", True):
    from django.contrib.staticfiles.views import serve as staticfiles_serve

    static_url = getattr(settings, "STATIC_URL", "/static/")
    static_url = static_url.replace(
        getattr(settings, "HTTP_ORIGIN", "http://localhost:8000"), ""
    )
    static_url = static_url.lstrip("/")
    urlpatterns = [
        url(
            r"^%s(?P<path>.*)" % (static_url,),
            staticfiles_serve,
            kwargs={
                "insecure": True,
            },
        )
    ] + urlpatterns

# Serve pattern library view only in debug mode or if explicitly declared
if getattr(settings, "DEBUG", True) or getattr(
    settings, "SERVE_PATTERN_LIBRARY", False
):
    urlpatterns = [
        url(
            r"^component-library$",
            TemplateView.as_view(template_name="component-library.html"),
            name="component-library",
        )
    ] + urlpatterns

# serve django debug toolbar if present
if settings.DEBUG and apps.is_installed("debug_toolbar"):
    try:
        import debug_toolbar

        urlpatterns = urlpatterns + [
            url(r"^__debug__/", include(debug_toolbar.urls)),
        ]
    except ImportError:
        pass

handler404 = error404
handler500 = error500
