package data.storage

import at.asitplus.KmmResult
import at.asitplus.iso.IssuerSigned
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsQueryList
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLExpectedClaimValue
import at.asitplus.openid.dcql.DCQLJsonClaimsQuery
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLSdJwtCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLSdJwtCredentialQuery
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.eupidsdjwt.EuPidSdJwtScheme
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.DisclosureDirective
import at.asitplus.wallet.lib.data.RelyingPartyContext
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.stateIn

/**
 * This class is used in order to reduce the time needed to load credentials from the store in HolderAgent
 * TODO: Evaluate, whether this takes too much memory or if the performance improvements are worth it
 */
class HotWalletSubjectCredentialStore(
    private val delegate: PersistentSubjectCredentialStore,
    val coroutineScope: CoroutineScope,
) : WalletSubjectCredentialStore, SubjectCredentialStore {
    override suspend fun reset() = delegate.reset()

    val hotStoreContainer: StateFlow<StoreContainer?> = delegate.observeStoreContainer().stateIn(
        scope = coroutineScope,
        started = SharingStarted.Eagerly,
        initialValue = null,
    )

    override fun observeStoreContainer(): Flow<StoreContainer> = hotStoreContainer.filterNotNull()

    override suspend fun getCredentials(credentialSchemes: Collection<ConstantIndex.CredentialScheme>?): KmmResult<List<SubjectCredentialStore.StoreEntry>> {
        val latestCredentials = observeStoreContainer().first().credentials.map { it.second }
        return credentialSchemes?.let { schemes ->
            KmmResult.success(latestCredentials.filter {
                when (it) {
                    is SubjectCredentialStore.StoreEntry.Iso -> it.scheme in schemes
                    is SubjectCredentialStore.StoreEntry.SdJwt -> it.scheme in schemes
                    is SubjectCredentialStore.StoreEntry.Vc -> it.scheme in schemes
                }
            }.toList())
        } ?: KmmResult.success(latestCredentials)
    }

    override suspend fun removeStoreEntryById(
        storeEntryId: StoreEntryId,
    ) = delegate.removeStoreEntryById(storeEntryId)

    override suspend fun storeCredential(
        vc: VerifiableCredentialJws,
        vcSerialized: String,
        scheme: ConstantIndex.CredentialScheme
    ): SubjectCredentialStore.StoreEntry = delegate.storeCredential(
        vc = vc,
        vcSerialized = vcSerialized,
        scheme = scheme,
    )

    override suspend fun storeCredential(
        vc: VerifiableCredentialSdJwt,
        vcSerialized: String,
        disclosures: Map<String, SelectiveDisclosureItem?>,
        scheme: ConstantIndex.CredentialScheme,
    ): SubjectCredentialStore.StoreEntry = delegate.storeCredential(
        vc = vc.copy(disclosurePolicy = buildTestDisclosurePolicy()),
        vcSerialized = vcSerialized,
        disclosures = disclosures,
        scheme = scheme,
    )

    override suspend fun storeCredential(
        issuerSigned: IssuerSigned,
        scheme: ConstantIndex.CredentialScheme
    ): SubjectCredentialStore.StoreEntry = delegate.storeCredential(
        issuerSigned = issuerSigned,
        scheme = scheme,
    )

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    /**
     * Builds a hardcoded list of [DisclosureDirective] instances for showcase purposes.
     *
     * This method demonstrates how disclosure policies could be attached to a credential at issuance time.
     * The policy restricts disclosure to only a certain set of EuPid claims
     * for the specific verifier identified by [VERIFIER_CLIENT_ID].
     *
     * **For testing and showcase purposes only. Do not use in production.**
     */
    private fun buildTestDisclosurePolicy(): List<DisclosureDirective> = listOf(
        DisclosureDirective(
            relyingPartyQuery = DCQLQuery(
                credentials = DCQLCredentialQueryList(
                    DCQLSdJwtCredentialQuery(
                        id = DCQLCredentialQueryIdentifier("rp_filter"),
                        format = CredentialFormatEnum.DC_SD_JWT,
                        meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(
                            vctValues = listOf(RelyingPartyContext.TYPE)
                        ),
                        claims = DCQLClaimsQueryList(
                            DCQLJsonClaimsQuery(
                                path = DCQLClaimsPathPointer("client_id"),
                                values = listOf(DCQLExpectedClaimValue.StringValue(VERIFIER_CLIENT_ID))
                            )
                        )
                    )
                )
            ),
            allowQuery = DCQLQuery(
                credentials = DCQLCredentialQueryList(
                    DCQLSdJwtCredentialQuery(
                        id = DCQLCredentialQueryIdentifier("allow_claims"),
                        format = CredentialFormatEnum.DC_SD_JWT,
                        meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(
                            vctValues = listOf(EuPidScheme.sdJwtType)
                        ),
                        claims = DCQLClaimsQueryList(
                            DCQLJsonClaimsQuery(
                                path = DCQLClaimsPathPointer(EuPidSdJwtScheme.SdJwtAttributes.FAMILY_NAME)
                            ),
                            DCQLJsonClaimsQuery(
                                path = DCQLClaimsPathPointer(EuPidSdJwtScheme.SdJwtAttributes.GIVEN_NAME)
                            ),
                            DCQLJsonClaimsQuery(
                                path = DCQLClaimsPathPointer(EuPidSdJwtScheme.SdJwtAttributes.BIRTH_DATE)
                            ),
                            DCQLJsonClaimsQuery(
                                path = DCQLClaimsPathPointer(EuPidScheme.Attributes.BIRTH_DATE)
                            ),
                            DCQLJsonClaimsQuery(
                                path = DCQLClaimsPathPointer(EuPidSdJwtScheme.SdJwtAttributes.ISSUANCE_DATE)
                            ),
                            DCQLJsonClaimsQuery(
                                path = DCQLClaimsPathPointer(EuPidScheme.Attributes.ISSUANCE_DATE)
                            ),
                            DCQLJsonClaimsQuery(
                                path = DCQLClaimsPathPointer(EuPidSdJwtScheme.SdJwtAttributes.EXPIRY_DATE)
                            ),
                            DCQLJsonClaimsQuery(
                                path = DCQLClaimsPathPointer(EuPidScheme.Attributes.EXPIRY_DATE)
                            ),
                            DCQLJsonClaimsQuery(
                                path = DCQLClaimsPathPointer(EuPidSdJwtScheme.SdJwtAttributes.ISSUING_COUNTRY)
                            ),
                            DCQLJsonClaimsQuery(
                                path = DCQLClaimsPathPointer(EuPidScheme.Attributes.ISSUING_COUNTRY)
                            ),
                        )
                    )
                )
            )
        )
    )

    companion object {
        /** Client ID of the test verifier targeted by the hardcoded disclosure policy. */
        private const val VERIFIER_CLIENT_ID = "AT-GV-EGIZ-CUSTOMVERIFIER"
    }
}