from django.urls import path
from .views import *

urlpatterns = [
    path ('signup/', SignUpView.as_view(), name='sign_up'),
    path ('login/', LoginView.as_view(), name='login'),
    path('verify_email/<uid>/<token>', VerifyEmailAddressView.as_view(), name='verify-email'),
    path('resend_verification_link/', ResendVerificationLinkView.as_view(), name='resend_verification_link'),
]