package com.example.demo.user;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Entity
@Table(name = "tu_company")
@Getter
@Setter
@ToString
@EqualsAndHashCode(of = "id")
public class Company implements Serializable {
  @Id
  @GeneratedValue(generator = "system-uuid")
  @GenericGenerator(name = "system-uuid", strategy = "uuid2")
  @Column(length = 50)
  private String id;


  private String name;


  @Column(name = "domain_name")
  private String domainName;

  @OneToMany(mappedBy = "company")
  private Set<SamlSetting> samlSettings = new HashSet<>();

  public Optional<SamlSetting> getSamlSetting(Idp idp) {
    return this.samlSettings.stream().filter(o -> o.getIdp() == idp).findFirst();
  }
}
