---
layout: "default"
description: ""
id: "laatusaannot"
status: "Keskeneräinen"
---
# Laatusäännöt
{:.no_toc}

1. 
{:toc}

## Johdanto

## Yhteiset laatusäännöt

### UML-mallin mukaisuus
{% include common/clause_start.html type="req" id="laatu/vaat-uml-mukaisuus" %}
Tietomallin loogisen tietomallin toteutusten tulee noudattaa tietomallin [UML-kielisen luokkakaavion](./uml/) määrityksiä luokkien attribuuttien ja assosiaatioiden kardinaliteetin ja tyypin suhteen.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="laatu/vaat-uml-toteutus" %}
Kunkin fyysisen tietomallin kuvauksessa tulee määritellä minkälaista rakennetta ja tietotyyppiä kukin loogisen tietomallin luokka ja attribuutin tyyppi vastaa fyysisessä mallissa. Attribuutit ja assosiaatiot, joiden kardinaliteetti on loogisessa tietomallissa ```0..1``` tai ```0..*``` voivat puuttua fyysisen tietomallin mukaisista objekteista.
{% include common/clause_end.html %}

### Tunnisteet ja sisäisten viittausten eheys
{% include common/clause_start.html type="req" id="laatu/vaat-tunnukset-viittaukset" %}
Tietomallin versioitavilla tietokohteilla tulee olla yksilöivät tunnukset, joiden luomisessa ja käyttämisessä viittaamiseen toisiin tietokohteisiin tulee noudattaa elinkaarisääntöjen luvun [Tunnukset ja niiden hallinta](elinkaarisaannot.html#tunnukset-ja-niiden-hallinta) vaatimuksia.
{% include common/clause_end.html %}

### Elinkaarisääntöjen mukaisuus
{% include common/clause_start.html type="req" id="laatu/vaat-elinkaarisaannot" %}
Tietomallin mukaisten aineistojen tulee noudattaa [elinkaarisääntöjen](elinkaarisaannot.html) vaatimuksia, ja niiden on suositeltavaa noudattaa elinkaarisääntöjen suosituksia. Vaatimukset ja suositukset on erotettu selkeästi elinkaarisääntöjen muusta sisällöstä.
{% include common/clause_end.html %}

### Merkkijonojen käyttö
#### Merkistöt
{% include common/clause_start.html type="req" id="laatu/vaat-merkisto-utf8" %}
Kaikki tietomallin tekstimuotoiset sisällöt on tiedonsiirtoa varten koodattava käyttäen UTF-8 -merkistökoodausta.
{% include common/clause_end.html %}

#### Monikielinen sisältö ja kielikoodit
Kaikki tietomallin tekstimuotoinen sisältö ilmaistaan ISO 19103 -standardin määrittelemän [LanguageString](dokumentaatio/#languagestring)-luokan avulla.

{% include common/clause_start.html type="req" id="laatu/vaat-monikielisyys-kielikoodi" %}
Kunkin LanguageString-luokan objektin tulee toteuttaa ```language```-attribuutti, jonka arvona on ISO 639-2 -standardin mukainen terminologinen, kolmekirjaiminen kielikoodi code (ISO 639-2/T).
{% include common/clause_end.html %}

{% include common/note.html content="ISO 639-2/T koodilistan mukaiset koodit Suomen virallisille kielille ovat ```fin``` (suomi), ```swe``` (ruotsi), ```smn``` (inarinsaami), ```sms```(koltansaami) ja ```sme``` (pohjoissaami). Muita Suomessa paljon puhuttujen kielten ISO 639-2/T -koodeja: ```rus``` (venäjä), ```est``` (viro), ```ara```(arabia),  ```eng``` (englanti), ```som``` (somali), ```kur``` (kurdi)." %}

Tekstimuotoiset attribuutit on määritelty siten, että ne sisältävät nolla tai enemmän LanguageString-tyyppisiä arvoja.

{% include common/clause_start.html type="req" id="laatu/vaat-yksi-teksti-per-kieli" %}
Kunkin tekstimuotoista sisältöä kuvaavan attribuutin arvoina tulee olla enintään yksi LanguageString-tyyppinen arvo kutakin kielikoodia (```language```-attribuutti) kohti.
{% include common/clause_end.html %}

#### Enimmäispituudet
{% include common/clause_start.html type="req" id="laatu/vaat-merkijono-pituus" %}
Kunkin yhdellä kielellä annetun LanguageString-tyyppisen merkkijonon enimmäispituus on 2048 merkkiä.
{% include common/clause_end.html %}

{% include common/note.html content="Valittu 2048 merkin raja perustuu arvioon tietomallissa tarvittavien merkkijonojen tyypillisistä pituuksista. Merkkijonojen enimmäispituuden määrääminen loogisen tietomallin tasolla on jossain määrin kajoamista mallin tekniseen toteutukseen, mutta yhteentoimivuuden takaamisen näkökulmasta on tärkeää, että kaikkissa fyysisissä tietomalleissa varataan yhtä suuri maksimimäärä merkkejä tekstisisältöjen tallentamiseen. Muutoin on riskinä oikeusvaikuttteisen tiedon katoaminen tiedonsiirrossa tai -käsittelyproseseissa." %}

### Geometriat

#### Geometriatyypit
{% include common/clause_start.html type="req" id="laatu/vaat-geom-piste-maar" %}
Pistemäiset geometriat toteuttavat ISO 19107 -standardin määrittelemän ```Point```-rajapinnan.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="laatu/vaat-geom-2d-alue-maar" %}
Aluemaiset geometriat toteuttavat ISO 19107 -standardin määrittelemän ```Surface```-rajapinnan.
{% include common/clause_end.html %}

{% include common/note.html content="Tietomalli ei vaadi kaikkien ISO 19107 -standardin mukaisten geometriatyyppien tukemista. Loogisen tietomallin mukaiset fyysiset tietomallit voivat rajoittaa mahdollisia geometriatyyppejä ja niiden ominaisuuksia." %}

#### Sallitut koordinaatistot ja koordinaattijärjestys

Rakennetun ympäristön tietojärjestelmä tukee seuraavia koordinaatistoja:

Tiedon luovutuksen koordinaatistot
* EPSG:4326, WGS84
  * Käytössä myös IFC-mallissa 
* EPSG:3857, Google Web Mercator
* Tiedon luovutusrajapinnan käyttäjä voi pyytää vastauksen haluamassaan tuetussa koordinaatistossa, jolloin tietojärjestelmä muuntaa tarvittaessa varannossa olevan tiedon haluttuun kohdekoordinaatistoon.

Tiedon luovutuksen ja vastaanoton koordinaatistot
* EPSG:3067, valtakunnallinen koordinaatisto.
* EPSG:3873-3885 koordinaatistot tiedon luovutuksessa / tiedon vastaanotossa
* Tiedon toimituksen yhteydessä tulee tallentaa tieto koordinaattijärjestelmästä ja korkeusjärjestelmästä (N2000), jossa tieto toimitettu.

{% include common/clause_start.html type="req" id="laatu/vaat-koord-jarjestys" %}
Geometrioiden ilmaisemisessa tulee noudattaa kunkin koordinaatiston määritelmässä annettua virallista koordinaattijärjestystä.
{% include common/clause_end.html %}

#### Geometrinen ja topologinen eheys

{% include common/clause_start.html type="req" id="laatu/vaat-suljetut-ringit" %}
Mikäli viiva on osa aluemaisen geometrian reunaviivaa, on sen oltava suljettu, eli sen alku- ja loppuppisteiden on oltava samat.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="laatu/vaat-alue-kielletyt-leikkaukset" %}
Aluemaisen geometrian ulkoreunan ja reikien reunaviivat eivät saa leikata itseään tai toisiaan. Kukin reunaviiva saa koskettaa alueen ulkoreunaa tai reiän reunaa, mukaanlukien se itse, vain yksittäisissä pisteissä.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="laatu/vaat-yhteneva-alue" %}
Aluemaisen geometrian sisäosan on oltava yhtenevä, eli minkä tahansa kahden alueen sisäpisteen välillä on voitava muodostaa yhtenäinen käyrä, joka kulkee kokonaan alueen sisällä.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="laatu/vaat-yhteneva-alue" %}
Aluemaisen geometrian sisäosan pinta-ala on oltava mitattavissa, eli alueeseen tulee sisältyä pisteitä, jotka eivät ole osa alueen ulkoreunaa.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="laatu/vaat-pinnan-orientaatio" %}
Aluemaisten geometrioiden kiertosuuntien tulee noudattaa ISO 19107 -standardin määritelmää: Geometrioiden reunojen kiertosuunnat tulee valita siten, että pinnan yläpuolelta katsottuna ulkorajan reunan kiertosuunta on vastapäivään ja pinnan mahdollisten reikien reunojen kiertosuunnat ovat myötäpäivään. Mikäli pinta on osa 3-ulotteisten geometrian ulkorajaa, ulkopuoli vastaa yläpuolta.
{% include common/clause_end.html %}

### Päivämäärät ja kelloanajat
Tietomallin yksittäisiä ajanhetkiä kuvaavat attribuutit ovat ISO 19108 -standardin määrittämää tyyppiä [TM_Instant](dokumentaatio/#tm_instant) ja aikavälejä kuvaavat attribuutit tyyppiä [TM_Period](dokumentaatio/#tm_period). Päivämäärät annetaan käyttäen Gregoriaanista kalenteria ja kellonajat käyttäen 24 tunnin kelloaikamuotoa alkaen kellonajasta 00:00:00.000  ja päättyen ajanhetkeen 23:59:59.999 (tunti, minuutti, sekunti, millisekunti).

{% include common/clause_start.html type="req" id="laatu/vaat-ajanhetki-tarkkuus" %}
Yksittäisiä ajanhetkiä kuvaavat attribuutit ilmaistaan joko pelkän päivämäärän tai päivämäärän ja kelloajan avulla. Päivämäärät ilmaistaan antamalla vuoden, kuukauden ja kuukauden päivän numeeriset arvot. Kellonajat ilmaistaan vähintään yhden minuutin ja enintään yhden millisekunnin tarkkuudella antamalla tunnin, minuutin, sekunnin ja millisekunnin numeeriset arvot.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="laatu/vaat-aikavyohykkeet" %}
Päivämäärien ja kellonaikojen yhteydessä voidaan antaa myös tieto aikavyöhykkeestä tai aikojen poikkeamasta UTC-ajasta. Mikäli muuta ei tietoa ei anneta, tulee ajanhetkitiedot tulkita siten, että ne kuvaavat Suomen aikaa noudattaen kyseisellä ajanhetkellä voimassaolleita asetuksia kesäaikaan liittyen.
{% include common/clause_end.html %}

{% include common/clause_start.html type="rec" id="laatu/suos-ajanhetki-muoto" %}
Mikäli fyysinen tietomalli ei aseta ajanhetken muodolle rajoituksia, on suositeltavaa käyttää [IETF RFC 3339 Date and Time on the Internet: Timestamps](https://tools.ietf.org/html/rfc3339)-standardin määrittelemää syntaksia.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="laatu/vaat-aikavali-maar" %}
Aikavälejä kuvaavat attribuutit voidaan antaa joko sekä alku- että loppuajanhetken avulla tai vain joko alku- tai loppuajanhetken avulla. Mikäli alkuajanhetkeä ei anneta, tulkitaan aikavälin sisältävän minkä tahansa ajanhetken loppuajanhetkeen saakka. Vastaavasti mikäli loppuajanhetkeä ei anneta, tulkitaan aikavälin sisältävän minkä tahansa ajanhetken alkujanhetkestä lähtien.
{% include common/clause_end.html %}

## Luokkakohtaiset säännöt

### RakentamislupaAsia

### Rakentamislupahakemus

### RakennetunYmpäristönLupapäätös

### Rakentamislupa

### Rakennuspaikka

### RakennuskohteenToimenpide

### Rakentamishanke

### Katselmus

### Ilmastoselvitys

{% include common/clause_start.html type="req" id="laatu/vaat-ilmastoselvitys-rakennuspaikan-pinta-ala-yksikko" %}
[Ilmastoselvitys](dokumentaatio/#ilmastoselvitys)-luokan ```rakennuspaikanPintaAla```-attribuutin arvon yksikön tulee olla neliömetri (```m2```).
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="laatu/vaat-ilmastoselvitys-arviointijakso-yksikko" %}
[Ilmastoselvitys](dokumentaatio/#ilmastoselvitys)-luokan ```käytetynArviointijaksonPituus```-attribuutin arvon yksikön tulee olla yksi vuosi (```a```).
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="laatu/vaat-ilmastoselvitys-rakennuksen-kayttoika-yksikko" %}
[Ilmastoselvitys](dokumentaatio/#ilmastoselvitys)-luokan ```rakennuksenTavoitteellinenKäyttöikä```-attribuutin arvon yksikön tulee olla yksi vuosi (```a```).
{% include common/clause_end.html %}

Ilmastoselvitys tulee voida aina liittää rakennukseen sen pysyvän rakennustunnuksen (PRT) kautta. Rakentamisen lupapäätösten tietomallissa [Ilmastoselvitys](dokumentaatio/#ilmaistoselvitys)-luokalla on ```1..*``` assosiaatio {% include common/moduleLink.html moduleId="rakennuskohteet" path="looginenmalli/dokumentaatio/#rakennuskohde" title="Rakennuskohde" %}-luokkaan, jonka konkreettisia aliluokkia ovat muun muassa {% include common/moduleLink.html moduleId="rakennuskohteet" path="looginenmalli/dokumentaatio/#rakennus" title="Rakennus" %} ja {% include common/moduleLink.html moduleId="rakennuskohteet" path="looginenmalli/dokumentaatio/#rakennuksenosa" title="RakennuksenOsa" %}. Ilmastoselvitys liitetään tavallisesti joko suoraan koko rakennusta kuvaavaan {% include common/moduleLink.html moduleId="rakennuskohteet" path="looginenmalli/dokumentaatio/#rakennus" title="Rakennus" %}-luokan objektiin tai siihen {% include common/moduleLink.html moduleId="rakennuskohteet" path="looginenmalli/dokumentaatio/#rakennuksenosa" title="RakennuksenOsa" %}-luokan objektiin, jota luvanvaraisella toimenpiteellä muutetaan, tai joka syntyy suunnitellun laajennuksen tuloksena. Jälkimmäisessä tapauksessa yhteys pyvyvään rakennustunnukseen syntyy {% include common/moduleLink.html moduleId="rakennuskohteet" path="looginenmalli/dokumentaatio/#rakennuksenosa" title="RakennuksenOsa" %}-luokan pakollisen ```rakennus:Rakennus```-assosiaation kautta.

{% include common/clause_start.html type="req" id="laatu/vaat-ilmastoselvitys-rakennuskohde-pysyva-rakennustunnus-oltava" %}
Kuhunkin [Ilmastoselvitys](dokumentaatio/#ilmastoselvitys)-luokan objektiin tulee liittyä vähintään yksi (1) {% include common/moduleLink.html moduleId="rakennuskohteet" path="looginenmalli/dokumentaatio/#rakennuskohde" title="Rakennuskohde" %}-luokan aliluokkien objekti, jonka kautta ilmastoselvitys voidaan liittää rakennuksen pysyvään rakennustunnukseen. 
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="laatu/vaat-ilmastoselvitys-kaikki-ostoenergian-lahteet-annettava" %}
Rakennusta tai sen osaa koskevan [Ilmastoselvitys](dokumentaatio/#ilmastoselvitys)-luokan objektin tulee sisältää tiedot ko. rakennuksen laskennallisesta ostoenergian kulutuksesta energialähteittäin. Kunkin energialähteen osuus ostoenergian arvioidusta kokonaiskulutuksesta annetaan oman ```rakennuksenLaskennallinenOstoenergianKulutus``` -attribuutin avulla.
{% include common/clause_end.html %}

#### Rakentamisen vähähiilisyyden arvioinnin tulosten arvot

Ilmastoselvityksen vähähiilisyystiedot ilmoitetaan joko suunnitellun rakentamistoimenpiteen arvioitua hiilijalan- tai -kädenjälkeä kuvaavina numeroarvoina.

{% include common/clause_start.html type="req" id="laatu/vaat-vahahiilisyystiedot-suureen-arvo" %}
Sekä [Rakennuskohteenvähähiilisyystiedot](dokumentaatio/#rakennuskohteenvähähiilisyystiedot)-luokkien että [RakennuspaikanVähähiilisyystiedot](dokumentaatio/rakennuspaikanvähähiilisystiedot)-luokkien vähähiilisyyden arvioinnin tuloksia koskevat ```ominaisuus```-attribuuttien arvot sekä hiilijalanjäljen että hiilikädenjäljen osalta annetaan luokan {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/#suureenarvo" title="SuureenArvo" %} objekteina siten, että niiden ```arvo```-attribuuttien arvot ovat luokan {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/#numeerinenarvo" title="NumeerinenArvo" %} objekteja, joiden attribuutin arvo ```yksikkö``` on hiilidioksidiekvivalenttikilogramma per pinta-alan neliö per vuosi (kgCO2e/m2/a), ja joiden ```numero``` -attribuutin arvo ilmoitettu pyöristettynä symmetrisesti kahden desimaalin tarkkuudella.
{% include common/clause_end.html %}

### Energiankulutus 

{% include common/clause_start.html type="req" id="laatu/vaat-energiamaaran-mittayksikko" %}
[Energiankulutus](dokumentaatio/#energiankulutus)-luokan objektin ```energiamääräVuodessa``` -attribuutin on oltava tyyppiä {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/#numeerinenarvo" title="NumeerinenArvo" %} ja sen ```mittayksikkö``` -attribuutin arvon on oltava kilowattitunti (```kWh```) tai megajoule (```MJ```).
{% include common/clause_end.html %}
 

### Hiilijalanjälkitiedot 

{% include common/clause_start.html type="req" id="laatu/vaat-hiilijalanjalkitiedon-jasen" %} 
[Hiilijalanjälkitiedot](dokumentaatio/#hiilijalanjälkitiedot)-luokan assosiaatio ```jäsen``` on rajoitettu viittaamaan vain [RakennuskohteenVähähiilisyystiedot](dokumentaatio/#rakennuskohteenvähähiilisyystiedot) tai [RakennuspaikanVähähiilisyystiedot](dokumentaatio/#rakennuspaikanvähähiilisyystiedot) -luokkien tai niiden aliluokkien objekteihin. 
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="laatu/vaat-hiilijalanjalkitiedon-jasen-per-rakennuspaikka" %}
[Hiilijalanjälkitiedot](dokumentaatio/#hiilijalanjälkitiedot)-luokan objekteilla tulee olla tasan yksi (1) ```jäsen```-assosiaatio, joka viittaa [RakennuspaikanVähähiilisyystiedot](dokumentaatio/rakennuspaikanvähähiilisystiedot)-luokan tai sen aliluokan objektiin.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="laatu/vaat-hiilijalanjalkitiedon-jasen-per-kayttotarkoitus" %}
[Hiilijalanjälkitiedot](dokumentaatio/#hiilijalanjälkitiedot)-luokan objekteilla tulee olla kutakin rakennuskohteen käyttötarkoitusta kohti tasan yksi (1) ```jäsen```-assosiaatio, joka viittaa [RakennuskohteenVähähiilisyystiedot](dokumentaatio/#rakennuskohteenvähähiilisyystiedot)-luokan tai sen aliluokan objektiin. 
{% include common/clause_end.html %}

#### Hiilijalanjälkitiedot rakennuksen elinkaaren vaiheittain

{% include common/clause_start.html type="req" id="laatu/vaat-hiilijalanjalki-rakennuksen-elinkaarienvaiheittain" %}
[Hiilijalanjälkitiedot](dokumentaatio/#hiilijalanjälkitiedot)-luokan objekteihin liitettyjen [Rakennuskohteenvähähiilisyystiedot](dokumentaatio/#rakennuskohteenvähähiilisyystiedot)-luokan ja [RakennuspaikanVähähiilisyystiedot](dokumentaatio/rakennuspaikanvähähiilisystiedot)-luokan objektien tulee sisältää arviot syntyvien hiilipäästöjen määristä seuraavien rakentamisen elinkaaren vaiheiden osalta:

* A1-3 - Rakennustuotteiden valmistus
* A4 - Kuljetukset
* A5 - Työmaatoiminnot
* B4 - Rakennustuotteiden vaihdot
* B6 - Energian käyttö
* C1 - Purkaminen
* C2 - Purkujätteen kuljetukset
* C3 - Purkujätteen käsittely
* C4 - Purkujätteen loppusijoitus

Yllä luetellut päästötiedot ilmoitetaan [Rakennuskohteenvähähiilisyystiedot](dokumentaatio/#rakennuskohteenvähähiilisyystiedot)- ja [RakennuspaikanVähähiilisyystiedot](dokumentaatio/rakennuspaikanvähähiilisystiedot)-luokkien yhteisen yläluokan {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/#tietoyksikkö" title="Tietoyksikkö" %} ```ominaisuus```-attribuutin arvojen avulla siten, että sekä [RakennuskohteenVähähiilisyystiedot](dokumentaatio/#rakennuskohteenvähähiilisyystiedot)-luokan objektit että [RakennuspaikanVähähiilisyystiedot](dokumentaatio/rakennuspaikanvähähiilisystiedot)-luokan objektit sisältävät tasan yhden (1) kappaleen kutakin yllä lueteltua rakennuksen elinkaaren vaiheen päästötietoa koskevaa ```ominaisuus```-attribuutin arvoa. Näiden ```ominaisuus```-attribuutin arvojen {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/#suureenarvo" title="SuureenArvo" %}-luokan ```suure```-attribuutin ```tunnus```-attribuutin arvojen on oltava [IlmastoselvityksenHiilijalanjälkisuure](dokumentaatio/#ilmastoselvityksenhiilijalanjälkisuure)-koodiston koodien tunnuksia. Muiden ```ominaisuus```-attribuutin arvojen käyttöä ei ole rajoitettu.
{% include common/clause_end.html %}

#### Hiilijalanjäljen summat rakennuksen koko toimenpidealan osalta

Useita eri käyttötarkoituksia sisältävän rakennuksen toimenpidealueen hiilijalanjälkitiedot ilmoitetaan erikseen kuhunkin käyttötarkoitukseen tarkoitetun lämmitetyn nettopinta-alan osalta. Koko toimenpidealueen kaikkien käyttötarkoituskohtaisten lämmitettyjen nettopinta-alojen hiilijalanjäljen osuuksien summaa (```kgCO2e/m2/a```) ei ilmoiteta erikseen, vaan se lasketaan ilmoitettujen käyttötarkoituskohtaisten hiilijalanjälkiarvioiden summana.

{% include common/clause_start.html type="req" id="laatu/vaat-hiilijalanjalki-summa-rakennukselle-per-ala-per-vuosi" %}
Rakentamistoimenpiteestä aiheutuva arvioitu hiilijalanjälki rakennuksen osalta toimenpidealueen lämmitettyä nettoneliömetriä kohti vuodessa lasketaan seuraavasti:
Kaikkien [Hiilijalanjälkitiedot](dokumentaatio/#hiilijalanjälki)-luokan objektiin liitettyjen [RakennuskohteenVähähiilisyystiedot](dokumentaatio/#rakennuskohteenvähähiilisyystiedot)-luokan objektien niiden ```ominaisuus```-attribuuttien ```arvo```-attribuuttien ```numero```-attribuuttien summa, joiden ```suure```-attribuutin ```tunnus```-attribuutin arvo on jokin [IlmastoselvityksenHiilijalanjälkisuure](dokumentaatio/#ilmastoselvityksenhiilijalanjälkisuure)-koodiston koodeista.
{% include common/clause_end.html %}

Seuraava pseudokoodiesitys kuvaa yllä kuvatun vaatimuksen laskenta-algoritmia:
```
let tulos = 0;
for each ilmastoselvitys.hiilijalanjälki.jäsen as j {
  if j instanceof RakennuksenVähähiilisyystiedot {
    for each j.ominaisuus as o {
      if IlmastoselvityksenHiilijalanjälkisuure.contains(o.suure.tunnus.koodi) {
        tulos = tulos + o.arvo.numero;
      }
    }
  }
}
```

Vastaavasti koko toimenpidealueen kaikkien käyttötarkoitusalueiden kokonaishiilijalanjäljen summaa (```kgCOe```) ei ilmoiteta erikseen, vaan se lasketaan ilmoitettujen käyttötarkoituskohtaisten hiilijalanjälkiarvioiden summana kerrottuna kunkin käyttötarkoituksen lämmitetyn nettoalan määrällä ja käytetyn arviontijakson pituudella. 

{% include common/clause_start.html type="req" id="laatu/vaat-hiilijalanjalki-summa-rakennukselle-arviointijaksolla" %}
Rakentamistoimenpiteestä aiheutuva arvioitu kokonaishiilijalanjälki rakennuksen toimenpidealueen osalta koko arviointijakson aikana lasketaan seuraavasti:
Kunkin [Hiilijalanjälkitiedot](dokumentaatio/#hiilijalanjälki)-luokan objektiin liitetyn [RakennuskohteenVähähiilisyystiedot](dokumentaatio/#rakennuskohteenvähähiilisyystiedot)-luokan objektin niiden ```ominaisuus```-attribuuttien ```arvo```-attribuuttien ```numero```-attribuuttien summa, joiden ```suure```-attribuutin ```tunnus```-attribuutin arvo on jokin [IlmastoselvityksenHiilijalanjälkisuure](dokumentaatio/#ilmastoselvityksenhiilijalanjälkisuure)-koodiston koodeista, kerrottuna sekä kyseisen [RakennuskohteenVähähiilisyystiedot](dokumentaatio/#rakennuskohteenvähähiilisyystiedot)-luokan objektin ```toimenpidealueenLämmitettyNettoala```-attribuutin ```value```-attribuutin arvolla että [Ilmastoselvitys](dokumentaatio/#ilmastoselvitys)-luokan objektin ```käytetynArviointijaksonPituus```-attribuutin ```value```-attribuutin arvolla.
{% include common/clause_end.html %}

Seuraava pseudokoodiesitys kuvaa yllä kuvatun vaatimuksen laskenta-algoritmia:
```
let tulos = 0;
for each ilmastoselvitys.hiilijalanjälki.jäsen as j {
  if j instanceof RakennuksenVähähiilisyystiedot {
    for each j.ominaisuus as o {
      if IlmastoselvityksenHiilijalanjälkisuure.contains(o.suure.tunnus.koodi) {
        tulos = tulos + (o.arvo.numero * j.toimenpidealueenLämmitettyNettoala.value);
      }
    }
  }
}
tulos = tulos * ilmastoselvitys.käytetynArviointijaksonPituus.value;
```

#### Hiilijalanjäljen summat rakennuksen käyttötarkoituksittain

Rakennuksen toimenpidealueen tiettyyn käyttötarkoitukseen tarkoitettua osaa koskevaa kaikkien sen rakentamisen elinkaaren vaiheiden hiilijalanjäljen summaa (```kgCO2e/m2/a```) ei ilmoiteta erikseen, vaan se lasketaan elinkaarenvaihekohtaisesti ilmoitettujen hiilijalanjälkitietojen summana. 

{% include common/clause_start.html type="req" id="laatu/vaat-hiilijalanjalki-summa-rakennuksen-kayttotarkoitukselle-per-ala-per-vuosi" %}
Rakentamistoimenpiteestä aiheutuva arvioitu hiilijalanjälki rakennuksen toimenpidealueen tiettyyn käyttötarkoitukseen tarkoitetun lämmitetyn nettoalan osalta neliömetriä kohti vuodessa lasketaan seuraavasti:
[Hiilijalanjälkitiedot](dokumentaatio/#hiilijalanjälki)-luokan objektiin liitetyn sen [RakennuskohteenVähähiilisyystiedot](dokumentaatio/#rakennuskohteenvähähiilisyystiedot)-luokan objektin, jonka ```käyttötarkoitusluokka```-attribuutin arvo vastaa haluttua käyttötarkoitusta, niiden ```ominaisuus```-attribuuttien ```arvo```-attribuuttien ```numero```-attribuuttien summa, jonka ```suure```-attribuutin ```tunnus```-attribuutin arvo on jokin [IlmastoselvityksenHiilijalanjälkisuure](dokumentaatio/#ilmastoselvityksenhiilijalanjälkisuure)-koodiston koodeista.
{% include common/clause_end.html %}

Seuraava pseudokoodiesitys kuvaa yllä kuvatun vaatimuksen laskenta-algoritmia (esimerkin käyttötapausluokka '2 - Asuinkerrostalo'):
```
let tulos = 0;
let kt = '2 - Asuinkerrostalo';
for each ilmastoselvitys.hiilijalanjälki.jäsen as j {
  if j instanceof RakennuksenVähähiilisyystiedot {
    if (j.käyttötarkoitusluokka == kt) {
      for each j.ominaisuus as o {
        if IlmastoselvityksenHiilijalanjälkisuure.contains(o.suure.tunnus.koodi) {
          tulos = tulos + o.arvo.numero;
        }
      }
    }
  }
}
```

Vastaavasti rakennuksen toimenpidealueen tiettyyn käyttötarkoitukseen tarkoitettua osaa koskevaa kokonaishiilijalanjälkeä (```kgCO2e```) ei ilmoiteta erikseen, vaan se lasketaan sen ko. käyttötarkoitusta koskevan rakennuksen osan elinkaarivaihekohtaisten arvojen summana kerrottuna ko. käyttötarkoituksen lämmitetyn nettoalan määrällä ja käytetyn arviontijakson pituudella.

{% include common/clause_start.html type="req" id="laatu/vaat-hiilijalanjalki-summa-rakennuksen-kayttotarkoitukselle-arviointijaksolla" %}
Rakentamistoimenpiteestä aiheutuva arvioitu kokonaishiilijalanjälki rakennuksen tiettyyn käyttötarkoitukseen tarkoitetun toimenpidealueen osalta koko arviointijakson aikana lasketaan seuraavasti:
[Hiilijalanjälkitiedot](dokumentaatio/#hiilijalanjälki)-luokan objektiin liitetyn sen[RakennuskohteenVähähiilisyystiedot](dokumentaatio/#rakennuskohteenvähähiilisyystiedot)-luokan objektin, jonka ```käyttötarkoitusluokka```-attribuutin arvo vastaa haluttua käyttötarkoitusta, niiden ```ominaisuus```-attribuuttien ```arvo```-attribuuttien ```numero```-attribuuttien summa, joiden ```suure```-attribuutin ```tunnus```-attribuutinarvo on jokin [IlmastoselvityksenHiilijalanjälkisuure](dokumentaatio/#ilmastoselvityksenhiilijalanjälkisuure)-koodiston koodeista, kerrottuna sekä kyseisen [RakennuskohteenVähähiilisyystiedot](dokumentaatio/#rakennuskohteenvähähiilisyystiedot)-luokan objektin ```toimenpidealueenLämmitettyNettoala```-attribuutin ```value```-attribuutin arvolla että [Ilmastoselvitys](dokumentaatio/#ilmastoselvitys)-luokan objektin ```käytetynArviointijaksonPituus```-attribuutin ```value```-attribuutin arvolla.
{% include common/clause_end.html %}

Seuraava pseudokoodiesitys kuvaa yllä kuvatun vaatimuksen laskenta-algoritmia (esimerkin käyttötapausluokka '2 - Asuinkerrostalo'):
```
let tulos = 0;
let kt = '2 - Asuinkerrostalo';
for each ilmastoselvitys.hiilijalanjälki.jäsen as j {
  if j instanceof RakennuksenVähähiilisyystiedot {
    if (j.käyttötarkoitusluokka == kt) {
      for each j.ominaisuus as o {
        if IlmastoselvityksenHiilijalanjälkisuure.contains(o.suure.tunnus.koodi) {
          tulos = tulos + (o.arvo.numero * j.toimenpidealueenLämmitettyNettoala.value;
        }
      }
    }
  }
}
tulos = tulos * ilmastoselvitys.käytetynArviointijaksonPituus.value;
```

#### Hiilijalanjäljen summat rakennuspaikan osalta

Samoin kuin rakennuksen osalta, rakennuspaikan ominaisuuksista johtuvan arvioidun rakentamisen hiilijalanjäljen yhteismäärää rakennuspaikan pinta-alan suhteen (```kgCO2e/m2/a```) ei ilmoiteta erikseen, vaan se lasketaan rakennuspaikan osalta eri rakentamisen elinkaarivaiheille ilmoitettujen arvojen summana. 

{% include common/clause_start.html type="req" id="laatu/vaat-hiilijalanjalki-summa-rakennuspaikalle-per-ala-per-vuosi" %}
Rakentamistoimenpiteestä aiheutuva arvioitu hiilijalanjälki rakennuspaikan osalta sen pinta-alan neliömetriä kohti vuodessa lasketaan seuraavasti:
[Hiilijalanjälkitiedot](dokumentaatio/#hiilijalanjälki)-luokan objektiin liitetyn [RakennuspaikanVähähiilisyystiedot](dokumentaatio/#rakennuspaikanvähähiilisyystiedot)-luokan objektin niiden ```ominaisuus```-attribuuttien ```arvo```-attribuuttien ```numero```-attribuuttien summa, joiden ```suure```-attribuutin ```tunnus```-attribuutin arvo on jokin [IlmastoselvityksenHiilijalanjälkisuure](dokumentaatio/#ilmastoselvityksenhiilijalanjälkisuure)-koodiston koodeista.
{% include common/clause_end.html %}

Seuraava pseudokoodiesitys kuvaa yllä kuvatun vaatimuksen laskenta-algoritmia:
```
let tulos = 0;
for each ilmastoselvitys.hiilijalanjälki.jäsen as j {
  if j instanceof RakennuspaikanVähähiilisyystiedot {
    for each j.ominaisuus as o {
      if IlmastoselvityksenHiilijalanjälkisuure.contains(o.suure.tunnus.koodi) {
        tulos = tulos + o.arvo.numero;
      }
    }
  }
}
```
Vastaavasti rakennuspaikan ominaisuuksista johtuvan kokonaishiilijalanjäljen arviota (```kgCO2e```) ei ilmoiteta erikseen, vaan se lasketaan ilmoitetuista rakentamisen elikaaren vaiheiden summana kerrotuna rakennuspaikan pinta-alan määrällä ja arviointijakson pituudella. 

{% include common/clause_start.html type="req" id="laatu/vaat-hiilijalanjalki-summa-rakennuspaikalle-arviointijaksolla" %}
Rakentamistoimenpiteestä aiheutuva arvioitu kokonaishiilijalanjälki rakennuspaikan osalta koko arviointijakson aikana lasketaan seuraavasti:
[Hiilijalanjälkitiedot](dokumentaatio/#hiilijalanjälki)-luokan objektiin liitetyn [RakennuspaikanVähähiilisyystiedot](dokumentaatio/#rakennuspaikanvähähiilisyystiedot)-luokan objektin niiden ```ominaisuus```-attribuuttien ```arvo```-attribuuttien ```numero```-attribuuttien summa, joiden ```suure```-attribuutin ```tunnus```-attribuutin arvo on jokin [IlmastoselvityksenHiilijalanjälkisuure](dokumentaatio/#ilmastoselvityksenhiilijalanjälkisuure)-koodiston koodeista, kerrottuna sekä [Ilmastoselvitys](dokumentaatio/#ilmastoselvitys)-luokan objektin ```käytetynArviointijaksonPituus```-attribuutin että ```rakennuspaikanPintaAla```-attribuutin ```value```-attribuuttien arvoilla.
{% include common/clause_end.html %}

Seuraava pseudokoodiesitys kuvaa yllä kuvatun vaatimuksen laskenta-algoritmia:
```
let tulos = 0;
for each ilmastoselvitys.hiilijalanjälki.jäsen as j {
  if j instanceof RakennuspaikanVähähiilisyystiedot {
    for each j.ominaisuus as o {
      if IlmastoselvityksenHiilijalanjälkisuure.contains(o.suure.tunnus.koodi) {
        tulos = tulos + o.arvo.numero;
      }
    }
  }
}
tulos = tulos * ilmastoselvitys.käytetynArviointijaksonPituus.value * ilmastoselvitys.rakennuspaikanPintaAla.value;
```

{% include common/clause_start.html type="req" id="laatu/vaat-hiilijalanjalki-paastosumma-yksikko" %}
Arvioidun kokonaishiilijalanjäljen ilmoittamisessa koko seuranta-ajanjaksolla sekä rakennuksen että rakennuspaikan osalta on käytettävä mittayksikköä hiilidioksidiekvivalenttikilogramma (```kgCO2e```).
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="laatu/vaat-hiilijalanjalki-per-ala-per-vuosi-yksikko" %}
Arvioidun hiilijalanjäljen ilmoittamisessa suhteessa pinta-alaan ja ajanjaksoon sekä rakennuksen lämmitetyn nettoalan että rakennuspaikan pinta-alan osalta on käytettävä mittayksikköä hiilidioksidiekvivalenttikilogramma per neliömetri per vuosi (```kgCO2e/m2/a```).
{% include common/clause_end.html %}
 

### Hiilikädenjälkitiedot 

{% include common/clause_start.html type="req" id="laatu/vaat-hiilikadenjalkitiedon-jasen" %} 
[Hiilikädenjälkitiedot](dokumentaatio/#hiilikädenjälkitiedot)-luokan assosiaatio ```jäsen``` on rajoitettu viittaamaan vain [RakennuskohteenVähähiilisyystiedot](dokumentaatio/#rakennuskohteenvähähiilisyystiedot) tai [RakennuspaikanVähähiilisyystiedot](dokumentaatio/#rakennuspaikanvähähiilisyystiedot) -luokkien tai niiden aliluokkien objekteihin. 
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="laatu/vaat-hiilikadenjalkitiedon-jasen-per-rakennuspaikka" %}
[Hiilikädenjälkitiedot](dokumentaatio/#hiilikädenjälkitiedot)-luokan objekteilla tulee olla tasan yksi (1) ```jäsen```-assosiaatio, joka viittaa [RakennuspaikanVähähiilisyystiedot](dokumentaatio/rakennuspaikanvähähiilisystiedot)-luokan tai sen aliluokan objektiin.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="laatu/vaat-hiilikadenjalkitiedon-jasen-per-kayttotarkoitus" %}
[Hiilikädenjälkitiedot](dokumentaatio/#hiilikädenjälkitiedot)-luokan objekteilla tulee olla kutakin rakennuskohteen käyttötarkoitusta kohti tasan yksi (1) ```jäsen```-assosiaatio, joka viittaa [RakennuskohteenVähähiilisyystiedot](dokumentaatio/#rakennuskohteenvähähiilisyystiedot)-luokan tai sen aliluokan objektiin. 
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="laatu/vaat-hiilikadenjalki-per-ala-per-vuosi-yksikko" %}
Arvioidun hiilikädenjäljen ilmoittamisessa suhteessa pinta-alaan ja ajanjaksoon sekä rakennuksen lämmitetyn nettoalan että rakennuspaikan pinta-alan osalta on käytettävä mittayksikköä hiilidioksidiekvivalenttikilogramma per neliömetri per vuosi (```kgCO2e/m2/a```).
{% include common/clause_end.html %}

#### Hiilikädenjälkitiedot osatekijöittäin

{% include common/clause_start.html type="req" id="laatu/vaat-hiilikadenjalki-osatekijoittain" %}
Sekä [Hiilikädenjälkitiedot](dokumentaatio/#hiilikädenjälkitiedot)-luokan objektiin liitettyjen [Rakennuskohteenvähähiilisyystiedot](dokumentaatio/#rakennuskohteenvähähiilisyystiedot)-luokan objektien että [RakennuspaikanVähähiilisyystiedot](dokumentaatio/rakennuspaikanvähähiilisystiedot)-luokan objektien tulee sisältää arviot vältettyjen tai poistettujen kasvihuonekaasupäästöjen määristä ennen rakennuksen käyttöä, rakennuksen käytön aikaa ja käytön jälkeistä aikaa seuraavien osatekijöiden osalta:

* D1 - Uudelleenkäyttö ja kierrätys
* D2 - Hyödyntäminen energiana
* D3 - Ylimääräinen uusiutuva energia
* D4 - Tuotteiden hiilivarastovaikutus
* D5 - Karbonatisoituminen
* D6 - Istutettu puusto

Hiilikädenjäljen arvioinnin on sisällettävä ainoastaan sellaiset vältetyt ja poistetut kasvihuonekaasupäästöt, joita ei aiheutuisi ilman rakennushanketta. Yllä luetellut osatekijöiden tiedot ilmoitetaan [Rakennuskohteenvähähiilisyystiedot](dokumentaatio/#rakennuskohteenvähähiilisyystiedot)- ja [RakennuspaikanVähähiilisyystiedot](dokumentaatio/rakennuspaikanvähähiilisystiedot)-luokkien yhteisen yläluokan {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/#tietoyksikkö" title="Tietoyksikkö" %} ```ominaisuus```-attribuutin arvojen avulla siten, että sekä [RakennuskohteenVähähiilisyystiedot](dokumentaatio/#rakennuskohteenvähähiilisyystiedot)-luokan objektit että [RakennuspaikanVähähiilisyystiedot](dokumentaatio/rakennuspaikanvähähiilisystiedot)-luokan objektit sisältävät tasan yhden (1) kappaleen kutakin yllä lueteltua osatekijää koskevaa ```ominaisuus```-attribuutin arvoa. Näiden ```ominaisuus```-attribuutin arvojen {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/#suureenarvo" title="SuureenArvo" %}-luokan ```suure```-attribuutin ```tunnus```-attribuutin arvojen on oltava [IlmastoselvityksenHiilikädenjälkisuure](dokumentaatio/#ilmastoselvityksenhiilikädenjälkisuure)-koodiston koodien tunnuksia. Muiden ```ominaisuus```-attribuutin arvojen käyttöä ei ole rajoitettu.
{% include common/clause_end.html %}

### RakennuskohteenVähähiilisyystiedot 

{% include common/clause_start.html type="req" id="laatu/vaat-rakennuskohteenvahahiilisyystiedot-kohdistus" %}
[RakennuskohteenVähähiilisyystiedot](dokumentaatio/#rakennuskohteenvahaliilisyystiedot)-luokan assosiaatio ```kohdistus``` on rajoitettu viittaamaan vain {% include common/moduleLink.html moduleId="rakennuskohteet" path="looginenmalli/dokumentaatio/#rakennuskohde" title="Rakennuskohde" %}-luokan tai sen aliluokkien objekteihin.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="laatu/vaat-rakennuskohteenvahahiilisyystiedot-ryhma" %} 
[RakennuskohteenVähähiilisyystiedot](dokumentaatio/#rakennuskohteenvahaliilisyystiedot)-luokan assosiaatio ```ryhmä``` on rajoitettu viittaamaan vain [Hiilijalanjälkitiedot](dokumentaatio/#hiilijalajjalkitiedot) tai [Hiilikädenjälkitiedot](dokumentaatio/hiilikadenjalkitiedot)-luokkien tai niiden aliluokkien objekteihin. 
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="laatu/vaat-rakennuskohteenvahahiilisyystiedot-arvot-per-pinta-ala-per-vuosi" %}
[RakennuskohteenVähähiilisyystiedot](dokumentaatio/#rakennuskohteenvahaliilisyystiedot)-luokan objektien hiilijalan- tai kädenjälken arvioinnin tuloksia kuvaavien ```ominaisuus```-attribuuttien numeeriset arvot annetaan hiilidioksidiekvivalenttikilogrammoina per rakennuskohteen annettuun käyttötarkoitukseen tarkoitetun osan lämmitetty nettoala per vuosi, yksikkönä ```kgCO2e/m2/a```.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="laatu/vaat-rakennuskohteenvahahiilisyystiedot-lammitetty-nettoala" %}
Rakennuksen lämmitetyllä nettoalalla tarkoitetaan lämmitettyjen kerrostasoalojen summaa kerrostasoja ympäröivien ulkoseinien sisäpintojen mukaan laskettuna. Rakennuksen lämmitetty nettoalalla kunkin käyttötarkoituksen osalta ilmoitetaan [RakennuskohteenVähähiilisyystiedot](dokumentaatio/#rakennuskohteenvahaliilisyystiedot)-luokan objektien ```toimenpidealueenLämmitettyNettoala```-attribuuttien avulla, yksikkönä neliömetri (```m2```).  
{% include common/clause_end.html %}

### RakennuspaikanVähähiilisyystiedot 

{% include common/clause_start.html type="req" id="laatu/vaat-rakennuspaikanvahahiilisyystiedot-kohdistus" %}
[RakennuspaikanVähähiilisyystiedot](dokumentaatio/#rakennuspaikanvahaliilisyystiedot)-luokan assosiaatio ```kohdistus``` on rajoitettu viittaamaan vain [Rakennuspaikka](dokumentaatio/#rakennuspaikka)-luokan tai sen aliluokkien objekteihin.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="laatu/vaat-rakennuspaikanvahahiilisyystiedot-ryhma" %} 
[RakennuspaikanVähähiilisyystiedot](dokumentaatio/#rakennuspaikanvahaliilisyystiedot)-luokan assosiaatio ```ryhmä``` on rajoitettu viittaamaan vain [Hiilijalanjälkitiedot](dokumentaatio/#hiilijalajjalkitiedot) tai [Hiilikädenjälkitiedot](dokumentaatio/hiilikadenjalkitiedot)-luokkien tai niiden aliluokkien objekteihin. 
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="laatu/vaat-rakennuspaikanvahahiilisyystiedot-arvot-per-pinta-ala-per-vuosi" %}
[RakennuspaikanVähähiilisyystiedot](dokumentaatio/#rakennuspaikanvahaliilisyystiedot)-luokan objektien hiilijalan- tai kädenjäljen arvioinnin tuloksia kuvaavien ```ominaisuus```-attribuuttien numeeriset arvot annetaan hiilidioksidiekvivalenttikilogrammoina per rakennuspaikan pinta-ala per vuosi, yksikkönä ```kgCO2e/m2/a```.
{% include common/clause_end.html %}
