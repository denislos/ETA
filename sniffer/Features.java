package mipt.information.defence;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.io.IOException;
import java.io.Writer;

public class Features {
  private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();


  public int source_port = 0;//this feature must not be included to neuronet
  public int dest_port = 0;
  public String sourceIp;//this feature must not be included to neuronet
  public String destinationIp;//this feature must not be included to neuronet
  public int selected_ciphersuite = 0;
  public int pkl = 384;
  public int san_entries = 0;
  public int certificate_validity = 0;
  public int TLS_RSA_WITH_RC4_128_MD5 = 0;//not set - 0; set - 1
  public int TLS_RSA_WITH_RC4_128_SHA = 0;
  public int TLS_RSA_WITH_IDEA_CBC_SHA = 0;
  public int TLS_RSA_WITH_DES_CBC_SHA = 0;
  public int TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0;
  public int TLS_DH_DSS_WITH_DES_CBC_SHA = 0;
  public int TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = 0;
  public int TLS_DH_RSA_WITH_DES_CBC_SHA = 0;
  public int TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = 0;
  public int TLS_DHE_DSS_WITH_DES_CBC_SHA = 0;
  public int TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = 0;
  public int TLS_DHE_RSA_WITH_DES_CBC_SHA = 0;
  public int TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0;
  public int TLS_KRB5_WITH_DES_CBC_SHA = 0;
  public int TLS_KRB5_WITH_3DES_EDE_CBC_SHA = 0;
  public int TLS_KRB5_WITH_RC4_128_SHA = 0;
  public int TLS_KRB5_WITH_IDEA_CBC_SHA = 0;
  public int TLS_KRB5_WITH_DES_CBC_MD5 = 0;
  public int TLS_KRB5_WITH_3DES_EDE_CBC_MD5 = 0;
  public int TLS_KRB5_WITH_RC4_128_MD5 = 0;
  public int TLS_RSA_WITH_AES_128_CBC_SHA = 0;
  public int TLS_DH_DSS_WITH_AES_128_CBC_SHA = 0;
  public int TLS_DH_RSA_WITH_AES_128_CBC_SHA = 0;
  public int TLS_DHE_DSS_WITH_AES_128_CBC_SHA = 0;
  public int TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0;
  public int TLS_RSA_WITH_AES_256_CBC_SHA = 0;
  public int TLS_DH_DSS_WITH_AES_256_CBC_SHA = 0;
  public int TLS_DH_RSA_WITH_AES_256_CBC_SHA = 0;
  public int TLS_DHE_DSS_WITH_AES_256_CBC_SHA = 0;
  public int TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0;
  public int TLS_RSA_WITH_AES_128_CBC_SHA256 = 0;
  public int TLS_RSA_WITH_AES_256_CBC_SHA256 = 0;
  public int TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = 0;
  public int TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = 0;
  public int TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = 0;
  public int TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0;
  public int TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = 0;
  public int TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = 0;
  public int TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = 0;
  public int TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0;
  public int TLS_PSK_WITH_RC4_128_SHA = 0;
  public int TLS_PSK_WITH_3DES_EDE_CBC_SHA = 0;
  public int TLS_PSK_WITH_AES_128_CBC_SHA = 0;
  public int TLS_PSK_WITH_AES_256_CBC_SHA = 0;
  public int TLS_DHE_PSK_WITH_RC4_128_SHA = 0;
  public int TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA = 0;
  public int TLS_DHE_PSK_WITH_AES_128_CBC_SHA = 0;
  public int TLS_DHE_PSK_WITH_AES_256_CBC_SHA = 0;
  public int TLS_RSA_PSK_WITH_RC4_128_SHA = 0;
  public int TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA = 0;
  public int TLS_RSA_PSK_WITH_AES_128_CBC_SHA = 0;
  public int TLS_RSA_PSK_WITH_AES_256_CBC_SHA = 0;
  public int TLS_RSA_WITH_AES_128_CCM = 0;
  public int TLS_RSA_WITH_AES_256_CCM = 0;
  public int TLS_DHE_RSA_WITH_AES_128_CCM = 0;
  public int TLS_DHE_RSA_WITH_AES_256_CCM = 0;
  public int TLS_RSA_WITH_AES_128_CCM_8 = 0;
  public int TLS_RSA_WITH_AES_256_CCM_8 = 0;
  public int TLS_DHE_RSA_WITH_AES_128_CCM_8 = 0;
  public int TLS_DHE_RSA_WITH_AES_256_CCM_8 = 0;
  public int TLS_PSK_WITH_AES_128_CCM = 0;
  public int TLS_PSK_WITH_AES_256_CCM = 0;
  public int TLS_DHE_PSK_WITH_AES_128_CCM = 0;
  public int TLS_DHE_PSK_WITH_AES_256_CCM = 0;
  public int TLS_PSK_WITH_AES_128_CCM_8 = 0;
  public int TLS_PSK_WITH_AES_256_CCM_8 = 0;
  public int TLS_PSK_DHE_WITH_AES_128_CCM_8 = 0;
  public int TLS_PSK_DHE_WITH_AES_256_CCM_8 = 0;
  public int TLS_ECDHE_ECDSA_WITH_AES_128_CCM = 0;
  public int TLS_ECDHE_ECDSA_WITH_AES_256_CCM = 0;
  public int TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = 0;
  public int TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 = 0;
  public int TLS_RSA_WITH_AES_128_GCM_SHA256 = 0;
  public int TLS_RSA_WITH_AES_256_GCM_SHA384 = 0;
  public int TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0;
  public int TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0;
  public int TLS_DH_RSA_WITH_AES_128_GCM_SHA256 = 0;
  public int TLS_DH_RSA_WITH_AES_256_GCM_SHA384 = 0;
  public int TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 = 0;
  public int TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 = 0;
  public int TLS_DH_DSS_WITH_AES_128_GCM_SHA256 = 0;
  public int TLS_DH_DSS_WITH_AES_256_GCM_SHA384 = 0;
  public int TLS_PSK_WITH_AES_128_GCM_SHA256 = 0;
  public int TLS_PSK_WITH_AES_256_GCM_SHA384 = 0;
  public int TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 = 0;
  public int TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 = 0;
  public int TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 = 0;
  public int TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 = 0;
  public int TLS_PSK_WITH_AES_128_CBC_SHA256 = 0;
  public int TLS_PSK_WITH_AES_256_CBC_SHA384 = 0;
  public int TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 = 0;
  public int TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 = 0;
  public int TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 = 0;
  public int TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 = 0;
  public int TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0;
  public int TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0;
  public int TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0;
  public int TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0;
  public int TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0;
  public int TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0;
  public int TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0;
  public int TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 = 0;
  public int TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 = 0;
  public int TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256 = 0;
  public int TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256 = 0;
  public int TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0;
  public int TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0;
  public int TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0;
  public int TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0;
  public int TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0;
  public int TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0;
  public int TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0;
  public int TLS_AES_128_GCM_SHA256 = 0;
  public int TLS_AES_256_GCM_SHA384 = 0;
  public int TLS_CHACHA20_POLY1305_SHA256 = 0;
  public int server_name = 0;
  public int max_fragment_length = 0;
  public int client_certificate_url = 0;
  public int trusted_ca_keys = 0;
  public int truncated_hmac = 0;
  public int status_request = 0;
  public int user_mapping = 0;
  public int client_authz = 0;
  public int server_authz = 0;
  public int cert_type = 0;
  public int supported_groups = 0;
  public int ec_point_formats = 0;
  public int srp = 0;
  public int signature_algorithms = 0;
  public int use_srtp = 0;
  public int heartbeat = 0;
  public int application_layer_protocol_negotiation = 0;
  public int status_request_v2 = 0;
  public int signed_certificate_timestamp = 0;
  public int client_certificate_type = 0;
  public int server_certificate_type = 0;
  public int padding = 0;
  public int encrypt_then_mac = 0;
  public int extended_master_secret = 0;
  public int token_binding = 0;
  public int cached_info = 0;
  public int compress_certificateed = 0;
  public int record_size_limit = 0;
  public int pwd_protect = 0;
  public int pwd_clear = 0;
  public int password_salt = 0;
  public int ticket_pinning = 0;
  public int session_ticket = 0;
  public int pre_shared_key = 0;
  public int early_data = 0;
  public int supported_versions = 0;
  public int cookie = 0;
  public int psk_key_exchange_modes = 0;
  public int certificate_authorities = 0;
  public int oid_filters = 0;
  public int post_handshake_auth = 0;
  public int signature_algorithms_cert = 0;
  public int key_share = 0;
  public int transparency_info = 0;
  public int connection_id = 0;
  public int external_id_hash = 0;
  public int external_session_id = 0;
  public int renegotiation_info = 0;
  public int next_protocol_negotiation = 0;
  public int server_name_selected = 0;
  public int max_fragment_length_selected = 0;
  public int client_certificate_url_selected = 0;
  public int trusted_ca_keys_selected = 0;
  public int truncated_hmac_selected = 0;
  public int status_request_selected = 0;
  public int user_mapping_selected = 0;
  public int client_authz_selected = 0;
  public int server_authz_selected = 0;
  public int cert_type_selected = 0;
  public int supported_groups_selected = 0;
  public int ec_point_formats_selected = 0;
  public int srp_selected = 0;
  public int use_srtp_selected = 0;
  public int heartbeat_selected = 0;
  public int application_layer_protocol_negotiation_selected = 0;
  public int status_request_v2_selected = 0;
  public int signed_certificate_timestamp_selected = 0;
  public int client_certificate_type_selected = 0;
  public int server_certificate_type_selected = 0;
  public int padding_selected = 0;
  public int encrypt_then_mac_selected = 0;
  public int extended_master_secret_selected = 0;
  public int token_binding_selected = 0;
  public int cached_info_selected = 0;
  public int compress_certificateed_selected = 0;
  public int record_size_limit_selected = 0;
  public int pwd_protect_selected = 0;
  public int pwd_clear_selected = 0;
  public int password_salt_selected = 0;
  public int ticket_pinning_selected = 0;
  public int session_ticket_selected = 0;
  public int pre_shared_key_selected = 0;
  public int early_data_selected = 0;
  public int supported_versions_selected = 0;
  public int cookie_selected = 0;
  public int psk_key_exchange_modes_selected = 0;
  public int certificate_authorities_selected = 0;
  public int oid_filters_selected = 0;
  public int post_handshake_auth_selected = 0;
  public int signature_algorithms_cert_selected = 0;
  public int key_share_selected = 0;
  public int transparency_info_selected = 0;
  public int connection_id_selected = 0;
  public int external_id_hash_selected = 0;
  public int external_session_id_selected = 0;
  public int renegotiation_info_selected = 0;
  public int next_protocol_negotiation_selected = 0;

  private boolean flagClientHello = false;
  private boolean flagServerHello = false;
  private boolean flagClientKey = false;
  private boolean flagServerKey = false;
  private boolean flagCertificate = false;

  public Features() {
  }

  public boolean setFlag(FlagToParser flag) {
    switch (flag) {
      case FLAGCERTIFICATE:
        flagCertificate = true;
        break;
      case FLAGCLIENTHELLO:
        flagClientHello = true;
        break;
      case FLAGSERVERHELLO:
        flagServerHello = true;
        break;
      case FLAGCLIENTKEYEXCHANGE:
        flagClientKey = true;
        break;
      case FLAGSERVERKEYEXCHANGE:
        flagServerKey = true;
        break;
      default:
        throw new UnsupportedOperationException();
    }
    return flagServerKey && flagClientKey && flagCertificate && flagClientHello && flagServerHello;
  }

  public void parseToJson(Writer file1) throws IOException {
    String json = GSON.toJson(this);
    file1.write(json);
    file1.write(",\n");
    file1.flush();
  }
}
