package mipt.information.defence;

public enum CipherSuites {
  TLS_RSA_WITH_RC4_128_MD5(0x00,0x04)  ,
  TLS_RSA_WITH_RC4_128_SHA(0x00,0x05)  ,
  TLS_RSA_WITH_IDEA_CBC_SHA(0x00,0x07)  ,
  TLS_RSA_WITH_DES_CBC_SHA(0x00,0x09)  ,
  TLS_RSA_WITH_3DES_EDE_CBC_SHA(0x00,0x0A)  ,
  TLS_DH_DSS_WITH_DES_CBC_SHA(0x00,0x0C)  ,
  TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA(0x00,0x0D)  ,
  TLS_DH_RSA_WITH_DES_CBC_SHA(0x00,0x0F)  ,
  TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA(0x00,0x10)  ,
  TLS_DHE_DSS_WITH_DES_CBC_SHA(0x00,0x12)  ,
  TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA(0x00,0x13)  ,
  TLS_DHE_RSA_WITH_DES_CBC_SHA(0x00,0x15)  ,
  TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA(0x00,0x16)  ,
  TLS_KRB5_WITH_DES_CBC_SHA(0x00,0x1E)  ,
  TLS_KRB5_WITH_3DES_EDE_CBC_SHA(0x00,0x1F)  ,
  TLS_KRB5_WITH_RC4_128_SHA(0x00,0x20)  ,
  TLS_KRB5_WITH_IDEA_CBC_SHA(0x00,0x21)  ,
  TLS_KRB5_WITH_DES_CBC_MD5(0x00,0x22)  ,
  TLS_KRB5_WITH_3DES_EDE_CBC_MD5(0x00,0x23)  ,
  TLS_KRB5_WITH_RC4_128_MD5(0x00,0x24)  ,
  TLS_RSA_WITH_AES_128_CBC_SHA(0x00,0x2F)  ,
  TLS_DH_DSS_WITH_AES_128_CBC_SHA(0x00,0x30)  ,
  TLS_DH_RSA_WITH_AES_128_CBC_SHA(0x00,0x31)  ,
  TLS_DHE_DSS_WITH_AES_128_CBC_SHA(0x00,0x32)  ,
  TLS_DHE_RSA_WITH_AES_128_CBC_SHA(0x00,0x33)  ,
  TLS_RSA_WITH_AES_256_CBC_SHA(0x00,0x35)  ,
  TLS_DH_DSS_WITH_AES_256_CBC_SHA(0x00,0x36)  ,
  TLS_DH_RSA_WITH_AES_256_CBC_SHA(0x00,0x37)  ,
  TLS_DHE_DSS_WITH_AES_256_CBC_SHA(0x00,0x38)  ,
  TLS_DHE_RSA_WITH_AES_256_CBC_SHA(0x00,0x39)  ,
  TLS_RSA_WITH_AES_128_CBC_SHA256(0x00,0x3C)  ,
  TLS_RSA_WITH_AES_256_CBC_SHA256(0x00,0x3D)  ,
  TLS_DH_DSS_WITH_AES_128_CBC_SHA256(0x00,0x3E)  ,
  TLS_DH_RSA_WITH_AES_128_CBC_SHA256(0x00,0x3F)  ,
  TLS_DHE_DSS_WITH_AES_128_CBC_SHA256(0x00,0x40)  ,
  TLS_DHE_RSA_WITH_AES_128_CBC_SHA256(0x00,0x67)  ,
  TLS_DH_DSS_WITH_AES_256_CBC_SHA256(0x00,0x68)  ,
  TLS_DH_RSA_WITH_AES_256_CBC_SHA256(0x00,0x69)  ,
  TLS_DHE_DSS_WITH_AES_256_CBC_SHA256(0x00,0x6A)  ,
  TLS_DHE_RSA_WITH_AES_256_CBC_SHA256(0x00,0x6B)  ,
  TLS_PSK_WITH_RC4_128_SHA(0x00,0x8A)  ,
  TLS_PSK_WITH_3DES_EDE_CBC_SHA(0x00,0x8B)  ,
  TLS_PSK_WITH_AES_128_CBC_SHA(0x00,0x8C)  ,
  TLS_PSK_WITH_AES_256_CBC_SHA(0x00,0x8D)  ,
  TLS_DHE_PSK_WITH_RC4_128_SHA(0x00,0x8E)  ,
  TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA(0x00,0x8F)  ,
  TLS_DHE_PSK_WITH_AES_128_CBC_SHA(0x00,0x90)  ,
  TLS_DHE_PSK_WITH_AES_256_CBC_SHA(0x00,0x91)  ,
  TLS_RSA_PSK_WITH_RC4_128_SHA(0x00,0x92)  ,
  TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA(0x00,0x93)  ,
  TLS_RSA_PSK_WITH_AES_128_CBC_SHA(0x00,0x94)  ,
  TLS_RSA_PSK_WITH_AES_256_CBC_SHA(0x00,0x95)  ,
  TLS_RSA_WITH_AES_128_CCM(0xC0,0x9C)  ,
  TLS_RSA_WITH_AES_256_CCM(0xC0,0x9D)  ,
  TLS_DHE_RSA_WITH_AES_128_CCM(0xC0,0x9E)  ,
  TLS_DHE_RSA_WITH_AES_256_CCM(0xC0,0x9F)  ,
  TLS_RSA_WITH_AES_128_CCM_8(0xC0,0xA0)  ,
  TLS_RSA_WITH_AES_256_CCM_8(0xC0,0xA1)  ,
  TLS_DHE_RSA_WITH_AES_128_CCM_8(0xC0,0xA2)  ,
  TLS_DHE_RSA_WITH_AES_256_CCM_8(0xC0,0xA3)  ,
  TLS_PSK_WITH_AES_128_CCM(0xC0,0xA4)  ,
  TLS_PSK_WITH_AES_256_CCM(0xC0,0xA5)  ,
  TLS_DHE_PSK_WITH_AES_128_CCM(0xC0,0xA6)  ,
  TLS_DHE_PSK_WITH_AES_256_CCM(0xC0,0xA7)  ,
  TLS_PSK_WITH_AES_128_CCM_8(0xC0,0xA8)  ,
  TLS_PSK_WITH_AES_256_CCM_8(0xC0,0xA9)  ,
  TLS_PSK_DHE_WITH_AES_128_CCM_8(0xC0,0xAA)  ,
  TLS_PSK_DHE_WITH_AES_256_CCM_8(0xC0,0xAB)  ,
  TLS_ECDHE_ECDSA_WITH_AES_128_CCM(0xC0,0xAC)  ,
  TLS_ECDHE_ECDSA_WITH_AES_256_CCM(0xC0,0xAD)  ,
  TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8(0xC0,0xAE)  ,
  TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8(0xC0,0xAF)  ,
  TLS_RSA_WITH_AES_128_GCM_SHA256(0x00,0x9C)  ,
  TLS_RSA_WITH_AES_256_GCM_SHA384(0x00,0x9D)  ,
  TLS_DHE_RSA_WITH_AES_128_GCM_SHA256(0x00,0x9E)  ,
  TLS_DHE_RSA_WITH_AES_256_GCM_SHA384(0x00,0x9F)  ,
  TLS_DH_RSA_WITH_AES_128_GCM_SHA256(0x00,0xA0)  ,
  TLS_DH_RSA_WITH_AES_256_GCM_SHA384(0x00,0xA1)  ,
  TLS_DHE_DSS_WITH_AES_128_GCM_SHA256(0x00,0xA2)  ,
  TLS_DHE_DSS_WITH_AES_256_GCM_SHA384(0x00,0xA3)  ,
  TLS_DH_DSS_WITH_AES_128_GCM_SHA256(0x00,0xA4)  ,
  TLS_DH_DSS_WITH_AES_256_GCM_SHA384(0x00,0xA5)  ,
  TLS_PSK_WITH_AES_128_GCM_SHA256(0x00,0xA8)  ,
  TLS_PSK_WITH_AES_256_GCM_SHA384(0x00,0xA9)  ,
  TLS_DHE_PSK_WITH_AES_128_GCM_SHA256(0x00,0xAA)  ,
  TLS_DHE_PSK_WITH_AES_256_GCM_SHA384(0x00,0xAB)  ,
  TLS_RSA_PSK_WITH_AES_128_GCM_SHA256(0x00,0xAC)  ,
  TLS_RSA_PSK_WITH_AES_256_GCM_SHA384(0x00,0xAD)  ,
  TLS_PSK_WITH_AES_128_CBC_SHA256(0x00,0xAE)  ,
  TLS_PSK_WITH_AES_256_CBC_SHA384(0x00,0xAF)  ,
  TLS_DHE_PSK_WITH_AES_128_CBC_SHA256(0x00,0xB2)  ,
  TLS_DHE_PSK_WITH_AES_256_CBC_SHA384(0x00,0xB3)  ,
  TLS_RSA_PSK_WITH_AES_128_CBC_SHA256(0x00,0xB6)  ,
  TLS_RSA_PSK_WITH_AES_256_CBC_SHA384(0x00,0xB7)  ,
  TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256(0xCC,0xA8)  ,
  TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256(0xCC,0xA9)  ,
  TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256(0xCC,0xAA)  ,
  TLS_PSK_WITH_CHACHA20_POLY1305_SHA256(0xCC,0xAB)  ,
  TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256(0xCC,0xAC)  ,
  TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256(0xCC,0xAD)  ,
  TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256(0xCC,0xAE)  ,
  TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256(0xD0,0x01)  ,
  TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384(0xD0,0x02)  ,
  TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256(0xD0,0x03)  ,
  TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256(0xD0,0x05)  ,
  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA(0xC0, 0x13)  ,
  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA(0xC0, 0x14)  ,
  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA(0xC0,0x09)  ,
  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA(0xC0,0x0A)  ,
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256(0xC0, 0x27)  ,
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256(0xC0,0x23)  ,
  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384(0xC0, 0x28)  ,
  TLS_AES_128_GCM_SHA256(0x13,0x01)  ,
  TLS_AES_256_GCM_SHA384(0x13,0x02)  ,
  TLS_CHACHA20_POLY1305_SHA256(0x13,0x03);

  private final int firstByte;
  private final int secondByte;

  public int getFirstByte() {
    return firstByte;
  }

  public int getSecondByte() {
    return secondByte;
  }

  CipherSuites(int firstByte, int secondByte) {
    this.firstByte = firstByte;
    this.secondByte = secondByte;
  }
}
