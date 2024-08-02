/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/Services.h"
#include "mozilla/StaticPrefs_security.h"
#include "nsIObserverService.h"
#include "nsThreadUtils.h"
#include "WebAuthnService.h"
#include "WebAuthnTransportIdentifiers.h"
#include <iostream>
#include <unistd.h>
#include "fido.h"

namespace mozilla::dom {

already_AddRefed<nsIWebAuthnService> NewWebAuthnService() {
  nsCOMPtr<nsIWebAuthnService> webauthnService(new WebAuthnService());
  return webauthnService.forget();
}

NS_IMPL_ISUPPORTS(WebAuthnService, nsIWebAuthnService)

NS_IMETHODIMP
WebAuthnService::MakeCredential(uint64_t aTransactionId,
                                uint64_t browsingContextId,
                                nsIWebAuthnRegisterArgs* aArgs,
                                nsIWebAuthnRegisterPromise* aPromise) {
  auto guard = mTransactionState.Lock();
  if (guard->isSome()) {
    guard->ref().service->Reset();
    *guard = Nothing();
  }
  *guard = Some(TransactionState{DefaultService()});
  nsCOMPtr<nsIRunnable> runnable(NS_NewRunnableFunction(
      "WebAuthnService::MakeCredential_Dbus",
      [self = RefPtr{this}, aArgs = RefPtr{aArgs}, aPromise = RefPtr{aPromise}]() mutable {
        fido_dbus::Attestation attestation;
        nsString origin, rpId, rpName, userName, userDisplayName, residentKey, userVerification, authenticatorAttachment, attestationConveyancePreference;
        nsCString clientDataJson;
        nsTArray<nsTArray<uint8_t >> excludeList;
        nsTArray<uint8_t> aChallenge, aClientDataHash, userId, excludeListTransports;
        nsTArray<int32_t> coseAlgs;
        bool credProps, hmacCreateSecret, minPinLength;
        uint32_t timeout;

        // parse params
        {
            mozilla::Unused << aArgs->GetOrigin(origin);
            mozilla::Unused << aArgs->GetChallenge(aChallenge);
            mozilla::Unused << aArgs->GetClientDataJSON(clientDataJson);
            mozilla::Unused << aArgs->GetClientDataHash(aClientDataHash);
            mozilla::Unused << aArgs->GetRpId(rpId);
            mozilla::Unused << aArgs->GetRpName(rpName);
                
            mozilla::Unused << aArgs->GetUserId(userId);
            mozilla::Unused << aArgs->GetUserName(userName);
            mozilla::Unused << aArgs->GetUserDisplayName(userDisplayName);

            mozilla::Unused << aArgs->GetCoseAlgs(coseAlgs);

            mozilla::Unused << aArgs->GetExcludeList(excludeList);
            mozilla::Unused << aArgs->GetExcludeListTransports(excludeListTransports);
            
            mozilla::Unused << aArgs->GetCredProps(&credProps);
            mozilla::Unused << aArgs->GetHmacCreateSecret(&hmacCreateSecret);
            mozilla::Unused << aArgs->GetMinPinLength(&minPinLength);

            mozilla::Unused << aArgs->GetResidentKey(residentKey) ;
            mozilla::Unused << aArgs->GetUserVerification(userVerification);
            mozilla::Unused << aArgs->GetAuthenticatorAttachment(authenticatorAttachment);
            mozilla::Unused << aArgs->GetTimeoutMS(&timeout);
            mozilla::Unused << aArgs->GetAttestationConveyancePreference(attestationConveyancePreference);
        }

        fido_dbus::RelyingParty rp{
            .id=NS_ConvertUTF16toUTF8(rpId).get(),
            .name=NS_ConvertUTF16toUTF8(rpName).get()
        };
        fido_dbus::UserEntity user{
            .id = std::vector<uint8_t>(userId.Elements(), userId.Elements() + userId.Length()),
            .name=NS_ConvertUTF16toUTF8(userName).get(),
            .displayName=NS_ConvertUTF16toUTF8(userDisplayName).get()
        };
        fido_dbus::CredentialParameters credentialParameters{
            .type = std::vector<std::string>(coseAlgs.Length(), "public-key"),
            .coseAlgs = std::vector<int32_t>(coseAlgs.Elements(), coseAlgs.Elements() + coseAlgs.Length())
        };
        std::vector<fido_dbus::CredentialDescriptor> credentialDescriptors;
        for(size_t i = 0; i < excludeList.Length(); i++){
            credentialDescriptors.push_back(fido_dbus::CredentialDescriptor{
                .transports=excludeListTransports.ElementAt(i),
                .credentialIds = std::vector<uint8_t>(excludeList.ElementAt(i).Elements(), excludeList.ElementAt(i).Elements() + excludeList.ElementAt(i).Length())
            });
        }
        fido_dbus::Extensions extensions{
            .credProps = credProps,
            .hmacCreateSecret = hmacCreateSecret,
            .minPinLength = minPinLength
        };

        std::vector<uint8_t> clientDataHash(aClientDataHash.Elements(), aClientDataHash.Elements() + aClientDataHash.Length());
        std::vector<uint8_t> challenge(aChallenge.Elements(), aChallenge.Elements() + aChallenge.Length());
        fido_dbus::Result result =  fido_dbus::MakeCredential(
            NS_ConvertUTF16toUTF8(origin).get(), challenge, 
            clientDataJson.get(), clientDataHash, 
            rp, 
            user, 
            credentialParameters, 
            credentialDescriptors,
            extensions, 
            NS_ConvertUTF16toUTF8(residentKey).get(), 
            NS_ConvertUTF16toUTF8(userVerification).get(), 
            NS_ConvertUTF16toUTF8(authenticatorAttachment).get(), 
            timeout,
            NS_ConvertUTF16toUTF8(attestationConveyancePreference).get(),

            attestation
        );
        if(result != fido_dbus::Result::SUCCESS){
          aPromise->Reject(NS_ERROR_DOM_NOT_ALLOWED_ERR);
          return;
        }

        nsTArray<uint8_t> aAttestationObject, aCredentialId;
        nsTArray<nsString> aTransports;
        nsString aAuthenticatorAttachment;
        nsCString aClientDataJSON;

        for (auto byte : attestation.attestationObject) {
            aAttestationObject.AppendElement(byte);
        }
        for (auto byte : attestation.credentialId) {
            aCredentialId.AppendElement(byte);
        }
        aArgs->GetClientDataJSON(aClientDataJSON);
        mozilla::Unused << aArgs->GetAuthenticatorAttachment(aAuthenticatorAttachment);
        mozilla::Maybe<nsCString> maybeClientData;
        maybeClientData.emplace(aClientDataJSON);
        mozilla::Maybe<nsString> maybeAttachment;
        maybeAttachment.emplace(aAuthenticatorAttachment);

        WebAuthnRegisterResult* registerResult = new WebAuthnRegisterResult(aAttestationObject, maybeClientData, aCredentialId, aTransports, maybeAttachment); 
        aPromise->Resolve(registerResult);
    })
  );
  NS_DispatchBackgroundTask(runnable, NS_DISPATCH_EVENT_MAY_BLOCK);
  return nsresult::NS_OK; //guard->ref().service->MakeCredential(aTransactionId, browsingContextId, aArgs, aPromise);
}

NS_IMETHODIMP
WebAuthnService::GetAssertion(uint64_t aTransactionId,
                              uint64_t browsingContextId,
                              nsIWebAuthnSignArgs* aArgs,
                              nsIWebAuthnSignPromise* aPromise) {
  auto guard = mTransactionState.Lock();
  if (guard->isSome()) {
    guard->ref().service->Reset();
    *guard = Nothing();
  }
  *guard = Some(TransactionState{DefaultService()});

#if defined(XP_MACOSX)
  // The macOS security key API doesn't handle the AppID extension. So we'll
  // use authenticator-rs if it's likely that the request requires AppID. We
  // consider it likely if 1) the AppID extension is present, 2) the allow list
  // is non-empty, and 3) none of the allowed credentials use the
  // "internal" or "hybrid" transport.
  nsString appId;
  rv = aArgs->GetAppId(appId);
  if (rv == NS_OK) {  // AppID is set
    uint8_t transportSet = 0;
    nsTArray<uint8_t> allowListTransports;
    Unused << aArgs->GetAllowListTransports(allowListTransports);
    for (const uint8_t& transport : allowListTransports) {
      transportSet |= transport;
    }
    uint8_t passkeyTransportMask =
        MOZ_WEBAUTHN_AUTHENTICATOR_TRANSPORT_ID_INTERNAL |
        MOZ_WEBAUTHN_AUTHENTICATOR_TRANSPORT_ID_HYBRID;
    if (allowListTransports.Length() > 0 &&
        (transportSet & passkeyTransportMask) == 0) {
      guard->ref().service = AuthrsService();
    }
  }
#endif
    nsCOMPtr<nsIRunnable> runnable(NS_NewRunnableFunction(
      "WebAuthnService::GetAssertion_Dbus",
      [self = RefPtr{this}, aArgs = RefPtr{aArgs}, aPromise = RefPtr{aPromise}]() mutable {
        fido_dbus::Assertion assertion;

        nsString origin, rpId, residentKey, userVerification, appId;
        nsCString aClientDataJson;
        nsTArray<nsTArray<uint8_t >> allowList;
        nsTArray<uint8_t> aChallenge, aClientDataHash, allowListTransports;
        bool conditionallyMediated, hmacCreateSecret;
        uint32_t timeout;

        // parse params
        {
            mozilla::Unused << aArgs->GetOrigin(origin);
            mozilla::Unused << aArgs->GetChallenge(aChallenge);
            mozilla::Unused << aArgs->GetClientDataJSON(aClientDataJson);
            mozilla::Unused << aArgs->GetClientDataHash(aClientDataHash);
            mozilla::Unused << aArgs->GetRpId(rpId);

            mozilla::Unused << aArgs->GetAllowList(allowList);
            mozilla::Unused << aArgs->GetAllowListTransports(allowListTransports);
            
            mozilla::Unused << aArgs->GetHmacCreateSecret(&hmacCreateSecret);

            mozilla::Unused << aArgs->GetAppId(appId);
            mozilla::Unused << aArgs->GetUserVerification(userVerification);

            mozilla::Unused << aArgs->GetTimeoutMS(&timeout);
            mozilla::Unused << aArgs->GetConditionallyMediated(&conditionallyMediated);
        }
        std::vector<fido_dbus::CredentialDescriptor> credentialDescriptors;
        for(size_t i = 0; i < allowList.Length(); i++){
            credentialDescriptors.push_back(fido_dbus::CredentialDescriptor{
                .transports=allowListTransports.ElementAt(i),
                .credentialIds = std::vector<uint8_t>(allowList.ElementAt(i).Elements(), allowList.ElementAt(i).Elements() + allowList.ElementAt(i).Length())
            });
        }

        std::vector<uint8_t> clientDataHash(aClientDataHash.Elements(), aClientDataHash.Elements() + aClientDataHash.Length());
        std::vector<uint8_t> challenge(aChallenge.Elements(), aChallenge.Elements() + aChallenge.Length());
        fido_dbus::Result result =  fido_dbus::GetAssertion(
            NS_ConvertUTF16toUTF8(origin).get(), challenge, 
            aClientDataJson.get(), clientDataHash, 
            NS_ConvertUTF16toUTF8(rpId).get(), 
            credentialDescriptors,
            hmacCreateSecret, 
            NS_ConvertUTF16toUTF8(appId).get(), 
            NS_ConvertUTF16toUTF8(userVerification).get(), 
            timeout,
            conditionallyMediated,

            assertion
        );


        if(result != fido_dbus::Result::SUCCESS){
          aPromise->Reject(NS_ERROR_DOM_NOT_ALLOWED_ERR);
          return;
        }

        nsTArray<uint8_t> aAuthenticatorData, aCredentialId, aSignature, aUserHandle;
        nsTArray<nsString> aTransports;
        for (auto byte : assertion.authenticatorData) {
            aAuthenticatorData.AppendElement(byte);
        }
        for (auto byte : assertion.credentialId) {
            aCredentialId.AppendElement(byte);
        }
        for (auto byte : assertion.signature) {
            aSignature.AppendElement(byte);
        }
        for (auto byte : assertion.userHandle) {
            aUserHandle.AppendElement(byte);
        }
  
        nsCString clientDataJson;
        nsString authenticatorAttachment;
        aArgs->GetClientDataJSON(clientDataJson);
        mozilla::Maybe<nsCString> maybeClientData;
        maybeClientData.emplace(clientDataJson);
        // sadly I don't know where to get this from ...
        mozilla::Maybe<nsString> maybeAttachment;

        WebAuthnSignResult* authenticateResult = new WebAuthnSignResult(aAuthenticatorData, maybeClientData, aCredentialId, aSignature, aUserHandle, maybeAttachment); 
        aPromise->Resolve(authenticateResult);

    })
  );
  NS_DispatchBackgroundTask(runnable, NS_DISPATCH_EVENT_MAY_BLOCK);
  /*rv = guard->ref().service->GetAssertion(aTransactionId, browsingContextId,
                                          aArgs, aPromise);
  if (NS_FAILED(rv)) {
    return rv;
  }*/

  // If this is a conditionally mediated request, notify observers that there
  // is a pending transaction. This is mainly useful in tests.
  bool conditionallyMediated;
  Unused << aArgs->GetConditionallyMediated(&conditionallyMediated);
  if (conditionallyMediated) {
    nsCOMPtr<nsIRunnable> runnable(NS_NewRunnableFunction(__func__, []() {
      nsCOMPtr<nsIObserverService> os = mozilla::services::GetObserverService();
      if (os) {
        os->NotifyObservers(nullptr, "webauthn:conditional-get-pending",
                            nullptr);
      }
    }));
    NS_DispatchToMainThread(runnable.forget());
  }

  return NS_OK;
}

NS_IMETHODIMP
WebAuthnService::GetIsUVPAA(bool* aAvailable) {
  return DefaultService()->GetIsUVPAA(aAvailable);
}

NS_IMETHODIMP
WebAuthnService::HasPendingConditionalGet(uint64_t aBrowsingContextId,
                                          const nsAString& aOrigin,
                                          uint64_t* aRv) {
  return SelectedService()->HasPendingConditionalGet(aBrowsingContextId,
                                                     aOrigin, aRv);
}

NS_IMETHODIMP
WebAuthnService::GetAutoFillEntries(
    uint64_t aTransactionId, nsTArray<RefPtr<nsIWebAuthnAutoFillEntry>>& aRv) {
  return SelectedService()->GetAutoFillEntries(aTransactionId, aRv);
}

NS_IMETHODIMP
WebAuthnService::SelectAutoFillEntry(uint64_t aTransactionId,
                                     const nsTArray<uint8_t>& aCredentialId) {
  return SelectedService()->SelectAutoFillEntry(aTransactionId, aCredentialId);
}

NS_IMETHODIMP
WebAuthnService::ResumeConditionalGet(uint64_t aTransactionId) {
  return SelectedService()->ResumeConditionalGet(aTransactionId);
}

NS_IMETHODIMP
WebAuthnService::Reset() {
  auto guard = mTransactionState.Lock();
  if (guard->isSome()) {
    guard->ref().service->Reset();
  }
  *guard = Nothing();
  return NS_OK;
}

NS_IMETHODIMP
WebAuthnService::Cancel(uint64_t aTransactionId) {
  return SelectedService()->Cancel(aTransactionId);
}

NS_IMETHODIMP
WebAuthnService::PinCallback(uint64_t aTransactionId, const nsACString& aPin) {
  return SelectedService()->PinCallback(aTransactionId, aPin);
}

NS_IMETHODIMP
WebAuthnService::ResumeMakeCredential(uint64_t aTransactionId,
                                      bool aForceNoneAttestation) {
  return SelectedService()->ResumeMakeCredential(aTransactionId,
                                                 aForceNoneAttestation);
}

NS_IMETHODIMP
WebAuthnService::SelectionCallback(uint64_t aTransactionId, uint64_t aIndex) {
  return SelectedService()->SelectionCallback(aTransactionId, aIndex);
}

NS_IMETHODIMP
WebAuthnService::AddVirtualAuthenticator(
    const nsACString& protocol, const nsACString& transport,
    bool hasResidentKey, bool hasUserVerification, bool isUserConsenting,
    bool isUserVerified, uint64_t* retval) {
  return SelectedService()->AddVirtualAuthenticator(
      protocol, transport, hasResidentKey, hasUserVerification,
      isUserConsenting, isUserVerified, retval);
}

NS_IMETHODIMP
WebAuthnService::RemoveVirtualAuthenticator(uint64_t authenticatorId) {
  return SelectedService()->RemoveVirtualAuthenticator(authenticatorId);
}

NS_IMETHODIMP
WebAuthnService::AddCredential(uint64_t authenticatorId,
                               const nsACString& credentialId,
                               bool isResidentCredential,
                               const nsACString& rpId,
                               const nsACString& privateKey,
                               const nsACString& userHandle,
                               uint32_t signCount) {
  return SelectedService()->AddCredential(authenticatorId, credentialId,
                                          isResidentCredential, rpId,
                                          privateKey, userHandle, signCount);
}

NS_IMETHODIMP
WebAuthnService::GetCredentials(
    uint64_t authenticatorId,
    nsTArray<RefPtr<nsICredentialParameters>>& retval) {
  return SelectedService()->GetCredentials(authenticatorId, retval);
}

NS_IMETHODIMP
WebAuthnService::RemoveCredential(uint64_t authenticatorId,
                                  const nsACString& credentialId) {
  return SelectedService()->RemoveCredential(authenticatorId, credentialId);
}

NS_IMETHODIMP
WebAuthnService::RemoveAllCredentials(uint64_t authenticatorId) {
  return SelectedService()->RemoveAllCredentials(authenticatorId);
}

NS_IMETHODIMP
WebAuthnService::SetUserVerified(uint64_t authenticatorId,
                                 bool isUserVerified) {
  return SelectedService()->SetUserVerified(authenticatorId, isUserVerified);
}

NS_IMETHODIMP
WebAuthnService::Listen() { return SelectedService()->Listen(); }

NS_IMETHODIMP
WebAuthnService::RunCommand(const nsACString& cmd) {
  return SelectedService()->RunCommand(cmd);
}

}  // namespace mozilla::dom
