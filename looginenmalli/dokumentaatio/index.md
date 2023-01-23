---
layout: "default"
description: ""
id: "dokumentaatio"
status: "Keskeneräinen"
---
# Loogisen tason rakentamiseen liittyvien lupapäätösten tietomalli
{:.no_toc}

{% include common/note.html content="Tietomallin dokumentaatio on toistaiseksi puutteellinen. Täydelliset luokkien, niiden attribuuttien ja assosiaatioden kuvaukset laaditaan mahdollisimman pian" %}

1. 
{:toc}

## Yleistä
Loogisen tason Rakentamisen lupapäätösten tietomalli määrittelee yhteiset tietorakenteet, joita käytetään luvanvaraisia rakentamis-, poikkeamis-, maisematyö- ja purkamistoimenpiteitä sisältävien lupa-asioiden, niihin liittyvien lupahakemusten ja -päätösten, myönnettyjen lupien, sekä rakentamishankkeiden ja katselmusten tietojen kuvaamiseen koneluettavassa rakenteisessa paikkatietomuodossa. Tietomallin luokkia tulee käyttää tietomallin [elinkaari](../elinkaarisaannot.html)- ja [laatusääntöjen](../laatusaannot.html) mukaisesti. Looginen tietomalli pyrkii olemaan mahdollisimman riippumaton tietystä toteutusteknologiasta tai tiedon fyysisestä esitystavasta (esim. relaatiotietokanta, tietyn ohjelmointikielen tietorakenteet, XML, JSON).

## Normatiiviset viittaukset
Seuraavat dokumentit ovat välttämättömiä tämän dokumentin täysipainoisessa soveltamisessa:
* {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/" title="Rakennetun ympäristön yhteiset tietokomponentit" %}, versio 1.0
* {% include common/moduleLink.html moduleId="rakennuskohteet" path="looginenmalli/dokumentaatio/" title="Rakennuskohteet ja huoneistot" %}, versio 1.0
* [ISO 639-2:1998 Codes for the representation of names of languages — Part 2: Alpha-3 code][ISO-639-2]
* [ISO 8601-1:2019 Date and time — Representations for information interchange — Part 1: Basic rules][ISO-8601-1]
* [ISO 19103:2015 Geographic information — Conceptual schema language][ISO-19103]
* [ISO 19107:2019 Geographic information — Spatial schema][ISO-19107]
* [ISO 19108:2002 Geographic information — Temporal schema][ISO-19108]
* [ISO 19109:2015 Geographic information — Rules for application schema][ISO-19109]
* [ISO 19505-2:ISO/IEC 19505-2:2012, Information technology — Object Management Group Unified Modeling Language (OMG UML) — Part 2: Superstructure][ISO-19505-2]

## Standardienmukaisuus
Kuvattu tietomalli perustuu [ISO 19109][ISO-19109]-standardin yleinen kohdetietomalliin (General Feature Model, GFM), joka määrittelee rakennuspalikat paikkatiedon ISO-standardiperheen mukaisten sovellusskeemojen määrittelyyn. GFM kuvaa muun muassa metaluokat ```FeatureType```, ```AttributeType``` ja ```FeatureAssociationType```. Kaavatietomallissa kaikki tietokohteet, joilla on tunnus ja jota voivat esiintyä erillään toisista kohteista on määritelty kohdetyypeinä (stereotyyppi ```FeatureType```. Sellaiset tietokohteet, joilla ei ole omaa tunnusta ja jotka voivat esiintyä vain kohdetyyppien attribuuttien arvoina on määritelty [ISO 19103][ISO-19103]-standardin ```DataType```-stereotyypin avulla. Lisäksi [HallinnollinenAlue](#hallinnollinenalue) ja [Organisaatio](#organisaatio) on mallinnettu vain rajapintojen (```Interface```) avulla, koska on niitä ei ole tarpeen kuvata kaavatietomallissa yksityiskohtaisesti, ja on todennäköistä, että tietovarastoja ylläpitävät tietojärjestelmät tarjovat niille konkreettiset toteuttavat luokat.

[ISO 19109][ISO-19109] -standardin lisäksi tietomalli perustuu muihin paikkatiedon ISO-standardeihin, joista keskeisimpiä ovat [ISO 19103][ISO-19103] (UML-kielen käyttö paikkatietojen mallinnuksessa), [ISO 19107][ISO-19107] (sijaintitiedon mallintaminen) ja [ISO 19108][ISO-19108] (aikaan sidotun tiedon mallintaminen).

### Muulla määritellyt luokat ja tietotyypit

#### Rakennetun ympäristön yhteiset tietokomponentit
Malli perustuu {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/" title="Rakennetun ympäristön yhteiset tietokomponentit" %} -kirjaston määrittelyille. Tässä mallissa hyönnetään suoraan seuraavia kirjaston luokkia:

* {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/#versioituobjekti" title="VersioituObjekti" %}
* {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/#liiteasiakirja" title="Liiteasiakirja" %}
* {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/#alueidenkäyttöjarakentamisasia" title="AlueidenkäyttöJaRakentamisasia" %}
* {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/#alueidenkäyttöjarakentamispäätös" title="AlueidenkäyttöJaRakentamispäätös" %}
* {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/#alueidenkäyttöjarakentamismääräys" title="AlueidenkäyttöJaRakentamismääräys" %}
* {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/#rakennetunympäristönlupaasia" title="RakennetunYmpäristönLupaAsia" %}
* {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/#rakennetunympäristönlupahakemus" title="RakennetunYmpäristönLupahakemus" %}
* {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/#rakennetunymäristönlupapäätös" title="RakennetunYmpäristönLupapäätös" %}
* {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/#rakennetunympäristönlupa" title="RakennetunYmpäristönLupa" %}
* {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/#toimija" title="Toimija" %}
* {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/#osoite" title="Osoite" %}
* {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/#kiinteistö" title="Kiinteistö" %}
* {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/#henkilö" title="Henkilö" %}
* {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/#abstraktiasiaelinkaaritila" title="AbstraktiAsianElinkaaritila" %}
* {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/#abstraktilupamääräyksenlaji" title="AbstraktiLupamääräyksenlaji" %}

#### Rakennuskohteet ja huoneistot -tietomallin luokat
Malli hyödyntää laajasti {% include common/moduleLink.html moduleId="rakennuskohteet" path="looginenmalli/dokumentaatio/" title="Rakennuskohteet ja huoneistot" %} -tietomallin määrittelyjä. Tässä mallissa hyönnetään suoraan seuraavia tietomallin luokkia:

* {% include common/moduleLink.html moduleId="rakennuskohteet" path="looginenmalli/dokumentaatio/#rakennussuunnitelma" title="Rakennussuunnitelma" %}
* {% include common/moduleLink.html moduleId="rakennuskohteet" path="looginenmalli/dokumentaatio/#erityissuunnitelma" title="Erityissuunnitelma" %}
* {% include common/moduleLink.html moduleId="rakennuskohteet" path="looginenmalli/dokumentaatio/#rakennustietomalli" title="Rakennustietomalli" %}
* {% include common/moduleLink.html moduleId="rakennuskohteet" path="looginenmalli/dokumentaatio/#rakennuskohteentoimenpide" title="RakennuskohteenToimenpide" %}
* {% include common/moduleLink.html moduleId="rakennuskohteet" path="looginenmalli/dokumentaatio/#rakennuskohteenmuutos" title="RakennuskohteenMuutos" %}
* {% include common/moduleLink.html moduleId="rakennuskohteet" path="looginenmalli/dokumentaatio/#rakennussuunnitelma" title="Rakennussuunnitelma" %}
* {% include common/moduleLink.html moduleId="rakennuskohteet" path="looginenmalli/dokumentaatio/#rakennuskohde" title="Rakennuskohde" %}
* {% include common/moduleLink.html moduleId="rakennuskohteet" path="looginenmalli/dokumentaatio/#huoneisto" title="Huoneisto" %}

#### CharacterString

Kuvaa yleisen merkkijonon, joka koostuu 0..* merkistä, merkkijonon pituudesta, merkistökoodista ja maksimipituudesta. Määritelty rajapinta-tyyppisenä [ISO 19103][ISO-19103]-standardissa.

#### LanguageString

Kuvaa kielikohtaisen merkkijonon. Laajentaa [CharacterString](#characterstring)-rajapintaa lisäämällä siihen ```language```-attribuutin, jonka arvo on ```LanguageCode```-koodiston arvo. Kielikoodi voi [ISO 19103][ISO-19103]-standardin määritelmän mukaan olla mikä tahansa ISO 639 -standardin osa.

#### Number

Kuvaa yleisen numeroarvon, joka voi olla kokonaisluku, desimaaliluku tai liukuluku. Määritelty rajapintana [ISO 19103][ISO-19103]-standardissa.

#### Integer

Laajentaa [Number](#number)-rajapintaa kuvaamaan numeron, joka on kokonaisluku ilman murto- tai desimaaliosaa. Määritelty rajapintana [ISO 19103][ISO-19103]-standardissa.

#### Decimal

Laajentaa [Number](#number)-rajapintaa kuvaamaan numeron, joka on desimaaliluku. Decimal-rajapinnan toteuttava numero voidaan ilmaista virheettä yhden kymmenysosan tarkkuudella. Määritelty rajapintana [ISO 19103][ISO-19103]-standardissa. Decimal-numeroita käytetään, kun desimaalien käsittelyn tulee olla tarkkaa, esim. rahaan liityvissä tehtävissä.

#### Real

Laajentaa [Number](#number)-rajapintaa kuvaamaan numeron, joka on tarkkudeltaan rajoitettu liukuluku. Real-rajapinnan numero voi ilmaista tarkasti vain luvut, jotka ovat 1/2:n (puolen) potensseja. Määritelty rajapintana [ISO 19103][ISO-19103]-standardissa. Käytännössä esitystarkkuus riippuu numeron tallentamiseen varattujen bittien määrästä, esim. ```float (32-bittinen)``` (tarkkuus 7 desimaalia) ja ```double (64-bittinen)``` (tarkkuus 15 desimaalia).

#### Measure

Mittattavan, numeerisen tiedon ja sen antamiseen käytetyn mittayksikön kuvaamiseen käytettävä yleiskäyttöinen tietorakenne. Määritelty [ISO 19103][ISO-19103]-standardissa. 

#### TM_Object

Aikamääreiden yhteinen yläluokka, käytetään, mikäli arvo voi olla joko yksittäinen ajanhetki tai aikaväli. Määritelty luokkana [ISO 19108][ISO-19108]-standardissa. 

#### TM_Instant

Kuvaa yksittäisen ajanhetken 0-ulotteisena ajan geometriana, joka vastaa pistettä avaruudessa. Määritelty luokkana [ISO 19108][ISO-19108]-standardissa. Aikapisteen arvo on määritelty ```TM_Position```-luokalla yhdistelmänä [ISO 8601][ISO-8601-1]-standin mukaisia päivämäärä- tai kellonaika-kenttiä tai näiden yhdistelmää, tai muuta ```TM_TemporalPosition```-luokan avulla kuvattua aikapistettä. Viimeksi mainitun luokan attribuutti ```indeterminatePosition``` mahdollistaa ei-täsmällisen ajanhetken ilmaisemisen liittämällä mahdolliseen arvoon luokittelun tuntematon, nyt, ennen, jälkeen tai nimi.

#### TM_Period

Kuvaa aikavälin [TM_Instant](#tm_instant)-tyyppisten ```begin```- ja ```end```-attribuuttien avulla. Molemmat attribuutit ovat pakollisia, mutta voivat sisältää tuntemattoman arvon  ```indeterminatePosition = unknown``` -attribuutin arvon avulla annettuna. Määritelty luokkana [ISO 19108][ISO-19108]-standardissa.

#### URI

Määrittää merkkijonomuotoisen Uniform Resource Identifier (URI) -tunnuksen [ISO 19103][ISO-19103]-standardissa. URIa voi käyttää joko pelkkänä tunnuksena tai resurssin paikantimena (Uniform Resource Locator, URL).

#### Geometry

Kaikkien geometria-tyyppien yhteinen rajapinta [ISO 19107][ISO-19107]-standardissa. Tyypillisimpiä [ISO 19107][ISO-19107]-standardin Geometry-rajapintaa laajentavia rajapintoja ovat ```Point```, ```Curve```, ```Surface``` ja ```Solid``` sekä ```Collection```, jota käyttämällä voidaan kuvata geometriakokoelmia (multipoint, multicurve, multisurface, multisolid).

#### Point
Täsmälleen yhdestä pisteestä koostuva geometriatyyppi. Määritelty rajapintana [ISO 19107][ISO-19107]-standardissa.

## Tietomallin yleispiirteet

## Rakentamisen luvat

### Rakentamislupahakemus

### RakentamislupaAsia

### Rakentamislupa

### ToimenpiteenJatkoaikapäätös

### Purkamislupahakemus

### PurkamislupaAsia

### Purkamislupa

### Maisematyölupahakemus

### MaisematyölupaAsia

### Maisematyölupa

### Poikkemaislupahakemus

### PoikkeamislupaAsia

### Poikkeamislupa

## Hankkeet ja katselmukset

### Rakentamishanke

### Katselmus

### HankkeenToimenpide

### Käyttöönottohyväksyntä

## Koodistot

### RakennusvalvontaAsianElinkaaritila

{% include common/codelistref.html registry="rytj" id="rakvalv-asian-elinkaaren-tila" name="Rakennusvalvonta-asian elinkaaren tila" %}

### RakennuslupamääräyksenLaji

{% include common/codelistref.html registry="rytj" id="Lupamaarayshierarkinen" name="Lupamääräys" %}

### RakennuskohteenToimenpiteenTila

{% include common/codelistref.html registry="rytj" id="rakkohteen-toimenpiteen-tila" name="Rakennuskohteen toimenpiteen tila" %}

### RakentamisluvanLaji

{% include common/codelistref.html registry="rytj" id="LuvanSisalto" name="Sijoittamis-/toteuttamislupa" %}

### KatsemuksenLopullisuudenLaji

{% include common/codelistref.html registry="rytj" id="OsittainenLopullinen" name="Katselmuksen lopullisuus (osittainen / lopullinen katselmus)" %}

### RakentamishankkeenKatselmuksenLaji

{% include common/codelistref.html registry="rytj" id="Katselmuslaji" name="Katselmuslaji" %}

### KatselmuksenTila

{% include common/codelistref.html registry="rytj" id="KatselmuksenTilanne" name="Katselmuksen tilanne" %}


[ISO-8601-1]: https://www.iso.org/standard/70907.html "ISO 8601-1:2019 Date and time — Representations for information interchange — Part 1: Basic rules"
[ISO-639-2]: https://www.iso.org/standard/4767.html "ISO 639-2:1998 Codes for the representation of names of languages — Part 2: Alpha-3 code"
[ISO-19103]: https://www.iso.org/standard/56734.html "ISO 19103:2015 Geographic information — Conceptual schema language"
[ISO-19107]: https://www.iso.org/standard/66175.html "ISO 19107:2019 Geographic information — Spatial schema"
[ISO-19108]: https://www.iso.org/standard/26013.html "ISO 19108:2002 Geographic information — Temporal schema"
[ISO-19109]: https://www.iso.org/standard/59193.html "ISO 19109:2015 Geographic information — Rules for application schema"
[ISO-19505-2]: https://www.iso.org/standard/52854.html "ISO/IEC 19505-2:2012, Information technology — Object Management Group Unified Modeling Language (OMG UML) — Part 2: Superstructure"