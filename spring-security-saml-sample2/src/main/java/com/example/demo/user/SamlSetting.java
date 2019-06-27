package com.example.demo.user;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import javax.persistence.UniqueConstraint;
import java.io.Serializable;

@Entity
@Table(name = "tu_saml_setting", uniqueConstraints = @UniqueConstraint(name = "ux_saml_idp", columnNames = {"company_id", "idp"}))
@Getter @Setter
@ToString
@EqualsAndHashCode(of = "id")
public class SamlSetting implements Serializable {

  private static final long serialVersionUID = -7169474063609963047L;

  @Id
  @GeneratedValue(generator = "system-uuid")
  @GenericGenerator(name = "system-uuid", strategy = "uuid2")
  @Column(length = 50)
  private String id;

  @OneToOne
  private Company company;

  @Enumerated(EnumType.STRING)
  private Idp idp;

  @Column(name = "entity_id")
  private String entityId;

  @Column(name = "sso_url")
  private String ssoUrl;

  @Column(name = "slo_url")
  private String sloUrl;

  @Lob
  private String cert;

}
