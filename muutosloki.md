---
layout: "default"
description: ""
id: "muutosloki"
---
# Muutosloki
{:.no_toc}

## 20.12.2022

- Päivitetty uusin ry-yhteiset- ja rakennuskohteet -riippuvuudet. Poistettu  Rakentamislupahakemus-luokan attribuutti elinkaaritila, peritytyy yläluokalta RakennetunYmpäristönLupahakemus
- Uudelleennimetty RakentamislupaAsianElinkaaritila -> RakennusvalvontaAsianElinkaaritila. Yhteinen rakentamis-, purkamis-, maisematyö-, ja poikkeamislupa-asioille.
- Lisätty luokat PoikeamislupaHakemus, PoikkeamislupaAsia, Poikkeamislupa, Maisematyölupahakemus, MaisematyölupaAsia, Maisematyölupa, Purkamislupahakemus, PurkamislupaAsia ja Purkamislupa, fixes #26
- 

## 7.12.2022

- Siirretty rakentamis- ja purkamistoimenpiteet ja ilmastoselvitys kokonaisuudessaan Rakentamisen lupapäätökset -tietomallista osaksi Rakennuskohteet ja huoneistot -tietomallia. Peruste: Rakennuskohteiden elinkaareen olennaisesti liittyvät rakentamis- ja purkamistoimenpiteet ovat nyt osa rakennuskohteiden tietomallia riippumatta siitä vaativatko ne rakentamislupaa vai eivät. Ilmastoselvityksen tiedot liittyvät rakennuskohteeseen ja rakentamistoimenpiteeseen, jotka molemmat nyt rakennuskohteiden tietomallissa. Mahdollistaa ilmastoselvityksen tuottamisen myös toimenpiteiden yhteydessä, joissa rakentamislupaa ei tarvita. Seuraavat luokat tuotu sellaisenaan lupapäätösten tietomallista: RakennuskohteenToimenpide, Rakentamistoimenpide, Purkamistoimenpide,  RakentamistoimenpiteenLaji, PurkamistoimenpiteenLaji, Ilmastoselvitys, Hiilijalanjälkitiedot, Hiilikädenjälkitiedot, Energiankulutus, RakennuskohteenVähähiilisyystiedot, RakennuspaikanVähähiilisyystiedot, PoikkeamisenPeruste, Energialähde, RakennuksenKäyttötarkoitusluokkaEnergiatehokkuudenArvioinnissa, IlmastoselvityksenrajaArvoistapoikkeamisenPerusteenLaji, IlmastoselvityksenHiilijalanjälkisuure, IlmastoselvityksenHiilikädenjälkisuure, Rakennuspaikka.
- Poistettu riippuvuus Kaavatiedot-tietomallista: ainoa kaavatiedoista riippunut luokka oli Rakennuspaikka, joka on siirretty Rakennukohteiden tietomalliin.

## 5.12.2022

- Siirretty RakennuskohteenMuutos-, HuoneistonMuutos- ja HuoneistonMuutoksenLaji-luokat Rakentamisen lupapäätökset -tietomallista Rakennukohteiden tietomalliin. Peruste: näin saadaan lupapäätösprosessista riippumaton rakennuskohteiden ja huoneistojen muutosten elinkaari kuvattua Rakennuskohteiden tietomallissa ilman riippuvuutta Rakentamissen lupapäätösten tietomalliin.
- Kun RakennuskohteenMuutos-luokka siirrettiin pois tietomallista, kytketty Rakentamistoimenpide-luokka suoraan Ilmastoselvitys-luokkaan kahdensuuntaisella assosiaatiolla.

## 2.12.2022

- Poistettu assosiaatio Katselmus.katselmuksenKohde: Katselmuksen liitos katselmoitavaan Rakentamiskohteeseen tulee jo kohteenMuutos-attribuutin (RakennuskohteenMuutos) kautta, ja olisi epäselvää, pitääkö katselmuksenKohde-assosiaation viitata kohteen versioon ennen suunniteltua muutosta, uusimpaan suunniteltuun kohteen versioon, vai katselmuksen hetkellä uusimpaan toteutuneeseen kohteen versioon.
- Tehty Katselmus.kohteenMuutos-attribuutista pakollinen (kardinaliteetti 0..* -> 1..*). Ilman tätä tietoa katselmusta ei voida liittää Rakennuskohteeseen.
- Muutettu attribuutin Katselmus.huomautukset nimi -> huomautus, ja kardinaliteetti 1 -> 0..*.
- Kokonaiset luonnosversiot sekä laatu- että elinkaarisäännöistä.

## 1.12.2022

- Uudelleenimetty Katselmus.toteutunutMuutos -> kohteenMuutos. Katselmuksen yhteydessä tai niiden välissä myös vain rakennuskohteen suunnitelmat saattavat muuttua, vaikka mitään ei olisi toteutettu.
- Uudelleennimetty selkeyden vuoksi ToimenpiteenJatkoaikapäätös.lupa -> jatkettuLupa. Sekaannusmahdollisuus perityn myönnettyLupa-assosiaation kanssa. Vaihdettu ToimenpiteenJatkoaikapäätös yläluokka RakennetunYmpäristönLupapäätös -> AlueidenkäyttöJaRakentamispäätös, koska ToimenpiteenJatkoaikapäätöksellä ei myönnetä lupaa.
- Lisätty attribuutti RakennetunYmpäristönLupapäätös.lupaMyönnetty.

## 30.11.2022

- Lisätty luokkaan Rakentamislupahakemus uusi pakollinen attribuutti 'elinkaaritila'.
- Uudelleennimetty DataType-luokka ToimenpiteenTila -> HankkeenToimenpide.
- Lisätty koodistot tyhjinä: RakentamislupahakemuksenElinkaaritila, RakennuskohteenToimenpiteenTila, RakentamishankkeenKatselmuksenLaji, KatselmuksenLopullisuudenLaji, KatselmuksenTila
- Uudelleennimetty selvyyden vuoksi assosiaatio Rakentamishanke.työnjohtaja -> vastaavaTyönjohtaja.
- Väljennetty Katselmus-luokan liittyväHanke-assosiaaation kardinaliteettia 1 -> 1..*. Sama katselmus voidaan näin liittää useampaan saman Rakentamishanke-objektin versioon.

## 25.11.2022

- Muutettu RakennuskohteenToimenpide-luokan attribuutin suunniteltuMuutos kardinaliteetti 0..* -> 1..* (tehty pakolliseksi). Ei ole mieltä kuvata toimenpidettä, jossa ei kuvata suunniteltua muutosta ja siten sen kohdistumista Rakennuskohteeseen.
- Poistettu RakennuskohteenToimenpide-luokan attribuutti `raukeamispäivämäärä`. Rakentamisluvissa ei anneta erikseen toimenpidekohtaisia määräaikoja, ja kun jatkoaika kuvataan erillisellä luokalla, niin toimenpiteen (alkuperäinen) raukeamispäivämäärä ei voi poiketa luvan (alkuperäisestä) raukeamispäivämäärästä.
- Muutettu RakennuskohteenToimenpide-luokan assosiaation `paikka:Rakennuspaikka` kardinaliteetti 0..* -> 1..* (tehty pakolliseksi).
- Lisätty Rakennuspaikka-luokalle rajoitus, joka tekee sen perityn `geometria`-attribuutin pakolliseksi.
- Muutettu RakennuskohteenToimenpide-luokan assosiaation `asia` kardinaliteetti 1 -> 0..1. Mahdollistaa myös ei-luvanvaraisten toimenpiteiden kuvaamisen (esim. pienten muutosten ilmoittaminen).
- Lisätty koodistot tyhjinä RakentamislupaAsianElinkaaritila, RakentamislupamääräyksenLaji, RakentamisluvanElinkaaritila, RakentamisluvanLaji, PurkamistoimenpiteenLaji, RakentamistoimenpiteenLaji ja HuoneistonMuutoksenLaji. Kytkentä Yhteentoimivuusalustan koodistoihin puuttuu toistaiseksi. Muutettu luokkien Rakentamislupahakemus, Rakentamislupa, Purkamistoimenpide, Rakentamistoimenpide ja HuoneistonMuutos koodistoattribuutit käyttämään luotuja koodilista-luokkia.
- Lisätty RakentamislupaAsia-luokkaan rajoitus, joka koskee ```elinkaaritila```-attribuutin tyyppiä.
- Lisätty Rakentamislupa-luokkaan rajoitus, joka koskee ```elinkaaritila```-attribuutin tyyppiä ja toinen, joka koskee ```määräys```-assosiaatiolla liitettävän Lupamääräys-luokan attribuutin ```määräyksenLaji``` tyyppiä.
- Luonnosteltu elinkaarisääntöjä 

## 17.11.2022

- Lisätty kuvailevaa tekstiä selittämään ilmastoselvitystä koskevien laatusääntöjen vaatimuksia.
- Korjattu alueen mitattavuutta koskevan vaatimuksen tunnus `laatu/vaat-yhteneva-alue` -> `laatu/vaat-mittava-alue`. Nyt `laatu/vaat-yhteneva-alue`-vaatimuksia on vain yksi.
- Tehty uusi luokkakaavio 'Hankkeen ja katselmukset' ja selvyyden vuoksi siirretty hankkeen aikana päivitettävät tiedot sinne Rakentamisen luvat -kaaviosta.
- Lisätty uusi luokka ToimenpiteenJatkoaikapäätös, poistettu RakennuskohteenToimenpide-luokasta attribuutti `jatkoajanPäättymispäivämäärä`. Perustelu: Näin lupapäätöksellä hyväksyttyä RakentamiskohteenToimenpide-luokan objektia ei tarvitse muuttaa jatkoajaikaluvan hyväksymisen yhteydessä.
- Ilmastoselvitys-luokka lisätty sekä Rakentamisen luvat - että Hankkeen ja katselmukset -kaaviolle.
- Järjestelty luokkakaavioita uudelleen selkeyttämistarkoituksessa.
- Lisätty ilmastoselvityksen laatusääntöjen vaatimukseen `laatu/vaat-hiilikadenjalki-osatekijoittain`  huomautus osatekijän D6 vaadittavuudesta ainoastaan asemakaava-alueella.

## 16.11.2022

- Lisätty ensimmäiset versiot laatu- ja elinkaarisäännöistä, painottuen ilmastoselvityksen tietoihin.

## 9.11.2022

- Muokattu Ilmastoselvitykseen liittyvien luokkien attribuuttien ja assosiaatioden pakollisuuksia vastaamaan valmiin ilmastoselvityksen vaatimuksia:
   - Ilmastoselvitys
      - rakennuspaikanPintaAla 0..1 -> 1
      - rakennuksenSuunniteltuKäyttäjämäärä 0..1 -> 1
      - rakennuksenLaskennallinenOstoenergianKulutus 0..* -> 1..*
      - rakennuksenTavoitteellinenKäyttöikä 0..1 -> 1
      - käytetytLaskentaohjelmistot 0..* -> 1..*
      - laatimuspäivä 0..1 -> 1
      - käytetynArviointijaksonPituus 0..1 -> 1
      - hiilijalanjälki 0..* -> 1
      - hiilikädenjälki 0..* -> 1
      - laatija 0..* -> 1..*
   - RakennuskohteenVähähiilisyystiedot
      - käyttötarkoitusluokka 1..* -> 1  
 - Lisätty Kaava-luokka ja Rakennuspaikka.rakentamistaOhjaavaKaava-assosiaatio näkyviin Ilmastoselvitys-luokkakaavioon.

## 7.11.2022

- Siirretty toimenpidealueenLämmitettyNettoala-attribuutti Ilmastoselvitys-luokasta RakennuskohteenVähähiilisyystiedot-luokkaan.
- Siirretty käytetynArviointijaksonPituus-attribuutti Hiilikädenjälkitiedot-luokasta Ilmastoselvitys-luokkaan.
- Muutettu rakennuksen käyttötarkoitusluokka -koodiston nimeksi RakennuksenKäyttötarkoitusluokkaEnergiatehokkuudenArvionnissa ja sanastoksi http://uri.suomi.fi/codelist/rytj/rak-kt-luokka-energiatehokkuus
- Lisätty sanastot koodistoluokkiin IlmastoselvityksenRajaArvoistapoikkeamisenPerusteenLaji, IlmastoselvityksenHiilijalanjälkisuure ja IlmastoselvityksenHiilikädenjälkisuure


## 4.11.2022

- Lisätty Ilmastoselvityksen 1. luonnoksen luokat ja niille oma luokkakaavionsa.
- EA-tiedosto on konvertoitu Firebase-formaattiin (feap). 
