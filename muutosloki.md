---
layout: "default"
description: ""
id: "muutosloki"
---
# Muutosloki
{:.no_toc}

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
