---
layout: "default"
description: ""
id: "muutosloki"
---
# Muutosloki
{:.no_toc}

## 17.11.2022

-  Lisätty kuvailevaa tekstiä selittämään ilmastoselvityksen laatusääntöjen vaatimuksia.

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
