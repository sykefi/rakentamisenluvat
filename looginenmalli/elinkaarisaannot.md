---
layout: "default"
description: ""
id: "elinkaarisaannot"
status: "Keskeneräinen"
---
# Elinkaarisäännöt
{:.no_toc}

1. 
{:toc}

## Johdanto

Rakentamisen lupapäätösten tietokohteilla on elinkaari, joka määrää miten kyseiset tietokohteet syntyvät, miten ne voivat muuttua elinkaarensa aikana, ja miten niiden elinkaari päättyy. Elinkaarisääntöjen määrittely liittyy olennaisesti tietokohteiden versionhallintaan, eli miten yksittäisten tietokohteiden niiden elinkaaren aikana muodotettavat versiot voidaan tallentaa ja yksilöidä viittauskelpoisten pysyvien tunnusten avulla. Tässä annetut säännöt pohjautuvat paikkatietokohteiden yksilöivien tunnusten ja elinkaarisääntöjen periaatteisiin, jotka on kuvattu jukishallinnon suosituksessa [JHS 193 - Paikkatiedon yksilöivät tunnukset](http://www.jhs-suositukset.fi/suomi/jhs193).

### HTTP URI -tunnukset

HTTP URI -muotoiset tunnukset ovat [RFC 3986 -standardiin](https://tools.ietf.org/html/rfc3986) perustuvia HTTP(S) -protokollan mukaisia URI-osoitteita (Uniform Resource Identifier), joiden globaali yksilöivyys varmistetaan Internetin DNS-nimipalveluun rekisteröityjen domain-nimien avulla. Kullakin DNS-palveluun rekisteröidyllä domain-nimellä (esim. ```uri.suomi.fi```) on yksiselitteinen omistaja, joka on suoraan tai välillisesti vastuussa ko. domain-nimen alla julkaistavasta sisällöstä. Nimen omistaja on myös ainoa taho, joka voi päättää ko. domain-nimeä käyttävien osoitteiden ohjautumisesta haluttuihin resursseihin, mikä tekee siitä luontevan perustan yksilöivien tunnusten nimiavaruuksille (esim. <http://uri.suomi.fi/object/rytj/kaava>). HTTP URI -muotoisen tunnuksen yksilöivyys perustuu siis domain-nimien ja siten niihin perustuvien nimiavaruuksien keskitettyyn hallintaprosessiin.

URI-tunnuksen ei tarvitse viitata konkreettiseen sijaintiin internetissä, vaan se voi olla abstraktimpi tunnus. [JHS 193 Paikkatiedon yksilöivät tunnukset](http://www.jhs-suositukset.fi/suomi/jhs193) määrittelee paikkatiedon yksilöiville tunnuksille muodon <http://paikkatiedot.fi/{tunnustyyppi}/{aineistotunnus}/{paikallinen tunnus}>, jossa paikkatietokohteiden ```tunnustyyppi``` on ```so```. Rakennennetun ympäristön yhteisiin tietokomponentteihin perustuvissa tietomalleissa on esimerkkinä käytetty tunnusmuotoa 
<http://uri.suomi.fi/object/rytj/{aineistotyyppi}/{TietotyypinNimi}/{paikallinenTunnus}>. HTTP URI -muotoisen tunnuksen etuna on luettavuus sekä DNS- ja HTTP-protokollien tarjoama kyky ratkaista (resolve) tunnus ja ohjata kysyjä sitä kuvaavaan Internet-resurssiin ilman tarvetta erityiselle keskitetylle tunnusrekisterille ja siihen perustuvalle ratkaisupalvelulle.

Tässä tietomallissa HTTP URI -muotoa käytetään [viittaustunnus](#viittaustunnus)-attribuutissa, jonka avulla viitataan tiettyyn versioon tietokohteesta tämän tietomallin ulkopuolelta.

### UUID-tunnukset
UUID (Universally Unique Identifier) on OSF:n (Open Software Foundation) määrittelemä standardoitu tunnusmuoto, jonka avulla voidaan luoda vakiokokoisia, hyvin suurella todennäköisyydellä yksilöiviä tunnuksia ilman keskitettyä hallintajärjestelmää. UUID-tunnukset voivat perustua satunnaislukuihin, aikaleimoihin, tietokoneiden verkkokorttien MAC-osoitteisiin tai merkkijonomuotoisiin nimiavaruuksiin eri yhdistelmissä. UUID-tunnukset erityisen hyvin tietojärjestelmissä, joissa uusia globaalisti pysyviä ja yksilöiviä tunnuksia on tarpeen luoda hajautetusti ilman keskitettyä tunnusrekisteriä.

Tässä tietomallissa UUID-muotoisia tunnuksia suositellaan käytettäväksi [identiteettitunnus](#identiteettitunnus)- ja [tuottajakohtainen tunnus](#tuottajakohtainen-tunnus)-attribuuttien arvoina.

## Tietomallin kohteiden elinkaaren hallinnan periaatteet
Tietomallin elinkaarisäännöt mahdollistavat mallin tietokohteiden käsittelyn, tallentamisen ja muuttamisen hallitusti sekä niiden laatimis- että voimassaolovaiheissa. Tietomallin mukaiset tietosisällöt ovat merkittäviä oikeusvaikutuksia aiheuttavia, juridisesti päteviä aineistoja, joita käsitellään hajautetusti eri toimijoiden tietojärjestelmissä. Tämän vuoksi niiden tunnusten, viittausten ja versionnin hallintaan on syytä kiinnittää erityistä huomiota.

Seuraavat keskeiset periaatteet ohjaavat tietomallin elinkaaren hallintaa:
* Kukin yhteen tietovarastoon tallennetuista tietokohteista saa pysyvän, versiokohtaisen tunnuksen.
* Kuhunkin yietovarastoon tallennettun tietokohteen versioon voidaan viitata sen pysyvän tunnuksen avulla.
* Tietomallin tietokohteiden väliset viittaukset toteutetaan hallitusti sekä tietoa tuottavissa tietojärjestelmissä että yhteisissä tietovarastoissa.
* Tietovarasto vastaa pysyvien tunnusten luomisesta ja antamisesta tallennettaville tietokohteille.

## Tunnukset ja niiden hallinta

### Identiteettitunnus
Identiteettitunnus yhdistää saman tietokohteen kehitysversiot toisiinsa.

{% include common/clause_start.html type="req" id="elinkaari/vaat-identiteettitunnus-maar" %}
Tietomallin tietokohteissa identiteettitunnus kuvataan attribuutilla ```identiteettiTunnus```. Kahdella tietomallin versioitavalla objektilla voi olla sama ```identiteettiTunnus```-attribuutin arvo ainoastaan, mikäli kaikki seuraavista ehdoista ovat tosia:
* Molemmat objektit kuvaavat saman tietokohteen kehityskaaren eri tiloja.
* Molemmat objektit ovat saman loogisen tietomallin luokan edustajia.
{% include common/clause_end.html %}

Yksittäisen tietokohteen tiettyyn tietovarastoon tallennettu kehityshistoria saadaan noutamalla kaikki ko. tyyppisen tietokohteen objektit, joilla on sama ```identiteettiTunnus```-attribuutin arvo.

Tietovarasto on vastuussa uusien identiteettitunnusten luomisesta tarvittaessa tallennustapahtumien yhteydessä, ja niiden välittämisestä tiedoksi tallentavalle tietojärjestelmälle. Tallentavan tietojärjestelmän tulee tallentaa itselleen kopiot tietovaraston tallennustapahtuman yhteydessä palautamista tietokohteiden identiteettitunnuksista, sillä ne tulee sisällyttää ko. tietokohteiden seuraavien versioden tallennettavaksi lähetettäviin objekteihin.

{% include common/clause_start.html type="req" id="elinkaari/vaat-identiteettitunnus-gen" %}
* Mikäli tallennettavalle tietokohteelle ei ole annettu ```identiteettitunnus```-attribuuttia, tai tietovarasto ei sisällä sellaista saman luokan tietokohdetta, jolla sama ```identiteettiTunnus```-attribuutin arvo, tietovarasto luo ko. objektille uuden identiteettitunnuksen, joka korvaa tuottavan tietojärjestelmän objektille mahdollisesti antaman ```identiteettiTunnus```-attribuutin arvon. Tällöin objektia pidetään uuden tietokohteen ensimmäisenä versiona.
* Mikäli tietovarasto sisältää saman luokan tietokohteen, jolla on sama ```identiteettiTunnus```-attribuutin arvo kuin tallennetavalla objektilla, objekti tallennetaan tietovarastoon ko. tietokohteen uutena versiona. Tällöin tallennettavan objektin ```identiteettiTunnus```-attribuutin arvo ei muutu.
{% include common/clause_end.html %}

{% include common/clause_start.html type="rec" id="elinkaari/suos-identiteettitunnus-form" %}
Identiteettitunnuksen suositeltu muoto on UUID.
{% include common/clause_end.html %}

Esimerkki: ```640bff6b-c16a-4947-af8d-d86f89106be1```

### Paikallinen tunnus
Paikallinen tunnus yksilöi tietokohteen yhden version tietovaraston sisällä. 

{% include common/clause_start.html type="req" id="elinkaari/vaat-paikallinentunnus-maar" %}
Tietomallin tietokohteissa paikallinen tunnus kuvataan attribuutilla ```paikallinenTunnus```. Kaikilla saman tietovaraston objekteilla (ml. saman tietokohteen eri versiot) tulee olla eri ```paikallinenTunnus```-attribuutin arvo.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="elinkaari/vaat-paikallinentunnus-gen" %}
Tietokohteiden paikallinen tunnus muuttuu sen jokaisen version tallennuksen yhteydessä. Tietovarasto vastaa paikallisten tunnusten luomisesta tallennustapahtuman yhteydessä. Tuottavan tietojärjestelmän mahdollisesti asettamat arvot korvataan.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="elinkaari/vaat-paikallinentunnus-form" %}
Paikallinen tunnus koostuu identiteettitunnuksesta ja siihen erotinmerkillä liitetystä versiokohtaisesta, esimerkiksi tarkkaan tallennusajanhetkeen perustuvasta merkkijonosta.
{% include common/clause_end.html %}

{% include common/clause_start.html type="rec" id="elinkaari/suos-paikallinentunnus-merk" %}
Paikallisen tunnuksen muodostamisessa tulee välttää merkkejä, jotka joudutaan URL-koodaamaan rajapintapalvelujen kutsuissa. Paikkatietokohteen paikallista tunnusta käytetään fyysisten tietomallien pääavaimena, esim. GeoJSON Feature ```id```-omaisuuden ja GML:n ```gml:id```-attribuutin arvona, ja siten esimerkiksi OGC Web Feature Service (WFS) - ja OGC API - Features -rajapintapalvelujen paikkatietokohteen yksilöivissä kyselyissä.
{% include common/clause_end.html %}

Tallennusajanhetkeen päättyvää paikallista tunnusta voidaan käyttää ilman sekaannusmahdollisuuksia samalla logiikalla myös paikallisissa versionneissa, eli sellaisissa tietokohteiden versioiden tallennuksissa, joita ei viedä lainkaan tietovarastoon.

Esimerkki: ```640bff6b-c16a-4947-af8d-d86f89106be1.b05cf48d46d8c905c54522f44b0a12daff11604e```

{% include common/note.html content="Käyttämällä paikallisena tunnuksena pelkkää identiteettitunnuksesta riippumatonta UUID-tunnusta päästäisiin lyhyempiin tunnuksiin, mutta menetetään yhteys identiteettitunnusten ja paikallisten tunnusten välillä, mikä saattaa hankaloittaa erilaisten vikatilanteiden selvitystä ja toimintavarmuuden testaamista, kun pelkkien tunnusten perusteella ei voida päätellä ovatko kaksi objektia saman tietokohteen eri versioita." %}

### Nimiavaruus
{% include common/clause_start.html type="req" id="elinkaari/vaat-nimiavaruus-maar" %}
Nimiavaruus määrää tietomallin kaikkien tietokohteiden viittaustunnusten alkuosan yhden tietovaraston sisällä. Tietomallin tietokohteissa paikallinen tunnus kuvataan attribuutilla ```nimiavaruus```.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="elinkaari/vaat-nimiavaruus-form" %}
Nimiavaruus on HTTP URI -muotoinen.
{% include common/clause_end.html %}

Nimiavaruus on syytä valita huolella siten, että se olisi mahdollisimman pysyvä, eikä sitä tarvitsisi tulevaisuudessa muuttaa esimerkiksi valtionhallinnon virastojen tai ministeriröiden mahdollisten uudelleenorganisointien ja -nimeämisten johdosta. Valittu URL-osoite tulee myös voida aina tarvittaessa ohjata kulloinkin käytössä olevaan rajapintapalveluun (HTTP redirect). 

{% include common/clause_start.html type="req" id="elinkaari/vaat-nimiavaruus-gen" %}
Tietovarasto vastaa ```nimiavaruus```-attribuuttien asetamisesta tallennustapahtuman yhteydessä. Tuottavan tietojärjestelmän mahdollisesti antamat arvot korvataan.
{% include common/clause_end.html %}

Esimerkki: ```http://uri.suomi.fi/object/rytj/raklupa```

### Viittaustunnus
{% include common/clause_start.html type="req" id="elinkaari/vaat-viittaustunnus-maar" %}
Viittaustunnus yksilöi tietokohteen yhden, tietovaraston tallentun kehitysversion globaalisti. Tietomallin tietokohteissa paikallinen tunnus kuvataan attribuutilla ```viittausTunnus```.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="elinkaari/vaat-viittaustunnus-form" %}
Viittaustunnus on HTTP URI -muotoinen ja se muodostuu nimiavaruudesta, tietokohteen luokan nimestä ja paikallisesta tunnuksesta yhdessä kauttaviivoilla (```/```) erotettuina.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="elinkaari/vaat-nimiavaruus-gen" %}
Tietovarasto vastaa ```viittausTunnus```-attribuuttien asetamisesta tallennustapahtuman yhteydessä. Tuottavan tietojärjestelmän mahdollisesti antamat arvot korvataan.
{% include common/clause_end.html %}

Tallentavan tietojärjestelmän ei siis tarvitse tallentaa luotuja viittaustunnuksia itselleen seuraavia tallennuksia varten.

{% include common/clause_start.html type="rec" id="elinkaari/suos-viittaustunnus-ohj" %}
Viittaustunnuksen on suositeltavaa ohjautua aina ko. tietokohteen version tietosisältöön kulloinkin toiminnassa olevassa tietovaraston latauspalvelussa.
{% include common/clause_end.html %}

Esimerkki: ```http://uri.suomi.fi/object/rytj/raklupa/BuildingPermit/640bff6b-c16a-4947-af8d-d86f89106be1.b05cf48d46d8c905c54522f44b0a12daff11604e```

### Tuottajakohtainen tunnus

{% include common/clause_start.html type="req" id="elinkaari/vaat-tuottajakohtainen-tunnus-maar" %}
Rakentamisen lupapäätöstietoa tuottavat järjestelmät voivat niin halutessaan käyttää tuottajakohtaista tunnusta niiden omien tietojärjestelmäspesifisten tunnusten antamiseen tietomallin tietokohteille. Tietomallin tietokohteissa tuottajakohtainen tunnus kuvataan attribuutilla ```tuottajakohtainenTunnus```.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="elinkaari/vaat-tuottajakohtainen-tunnus-gen" %}
Tietovarasto ei koskaan muuta tuottavan tietojärjestelmän mahdollisesti asettamia tuottajakohtaisia tunnuksia, ja ne palautetaan sellaisenaan latattaessa tietokohteita tietovarastosta.
{% include common/clause_end.html %}

Tietojärjestelmät voivat käyttää tuottajakohtaisia tunnuksia kohdistamaan tietovarastoon ja paikallisiin tietojärjestelmiin tallennettuja tietokohteita toisiinsa esimerkiksi päivitettäessä niiden tallennuksen yhteydessä syntyneitä tunnuksia, vertailtaessa tietovarastoon tallennettuja kohteita ja paikallisia kohteita toisiinsa, sekä esitettäessä validointipalvelun tuloksia suunnitteluohjelmiston käyttäjälle.

Tuottajakohtaisilta tunnuksilta ei vaadita yksilöivyyttä tai mitään tiettyä yhtenäistä muotoa, mutta UUID-muodon käyttäminen tarjoaa hyvin määritellyn ja standardoidun tavan luoda tuottajakohtaisista tunnuksista yksilöiviä eri tietojärjestelmien kesken. Tästä saattaa olla etua haluttaessa tehdä tuotettavista rakentamisen lupapäätösten tiedoista mahdollisimman järjestelmäriippumattomia ja esimerkiksi taata tuottajakohtaisten tunnusten yksilöivyys yli mahdollisten lupapäätöstietoa tuottavien tietojärjestelmien vaihdosten ja päivitysten. 

{% include common/clause_start.html type="rec" id="elinkaari/suos-tuottajakohtainen-tunnus-form" %}
Tuottajakohtaisen tunnuksen suositeltu muoto on UUID.
{% include common/clause_end.html %}

Esimerkki: ```k-123445```


### Pysyvien tunnusten palauttaminen tuottavalle järjestelmälle

Versionhallinnan näkökulmasta on tärkeää, että rakentamisen lupapäätösten tietoja tuottava tietojärjestelmä käyttää samaa, tietovarastoon tallennettua tietokohdetta päivtettäessä sen ensimmäisen tallennuksen yhteydessä luotua identiteettitunnusta, mikäli objektin katsotaan kuvaavan ko. tietokohteen uutta versiota.

{% include common/clause_start.html type="req" id="elinkaari/vaat-tunnusten-palautus" %}
Tietovaraston tallennusrajapinta palauttaa tallennetun rakentamisen lupapäätöksen tiedot tuottavalle tietojärjestelmälle tallennusoperaation yhteydessä siten, että ne sisältävät yllä mainittujen tunnustenhallintasääntöjen mukaisesti mahdollisesti generoidut tai muokatut identiteettitunnukset, paikalliset tunnukset, nimiavaruudet ja viittaustunnukset kaikille tallennetuille tietokohteille.
{% include common/clause_end.html %}

### Tietokohteisiin viittaaminen ja viitteiden ylläpito

{% include common/clause_start.html type="req" id="elinkaari/vaat-sisaiset-viittaukset" %}
Saman rakentamisen lupapäätöksen tietokohteiden keskinäiset assosiaatiot toteutetaan viitattavan tietokohteen [paikallinenTunnus](#paikallinen-tunnus)-attribuuttia käyttäen.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="elinkaari/vaat-tietovaraston-sisaiset-viittaukset" %}
Tietokohteiden assosiaatiot eri tietomallien tietokohteiden välillä toteutetaan viitattavan tietokohteen [viittaustunnus](#viittaustunnus)-attribuuttia käyttäen. Tämä koskee myös viittauksia Rakennuskohteiden tietomallissa ja Kaavatietomallissa määriteltyihin tietokohteisiin.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="elinkaari/vaat-viittaukset-ulkoa" %}
Pysyvät viittaukset tietomallin tietokohteisiin ulkopuolisista tietojärjestelmistä toteutetaan viitattavan tietokohteen [viittaustunnus](#viittaustunnus)-attribuuttia käyttäen.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="elinkaari/vaat-viittaukset-tallennettaessa" %}
Tallennettaessa tietomallin tietokohteita tietovarastoon tietokohteiden tunnukset muuttuvat niiden pysyvään muotoon, kuten kuvattu luvussa [Tunnukset ja niiden hallinta](#tunnukset-ja-niiden-hallinta). Tietovaraston vastuulla on päivittää kunkin paikallisen tunnuksen muuttamisen yhteydessä myös kaikkien ko. tietokohteen versioon sen paikallisen tunnuksen avulla viittaavien muiden ko. rakentamisen lupapäätöksen tietokohteiden viittaukset käyttämään tietokohteen muutettua paikallista tunnusta.   
{% include common/clause_end.html %}

### Koodistojen koodien tunnuksiin liittyvät vaatimukset

{% include common/clause_start.html type="req" id="elinkaari/vaat-koodien-yksiloivat-tunnukset" %}
Kullakin koodiston koodilla on oltava pysyvä tunnus, joka sellaisenaan yksilöi kyseisen koodin globaalisti ilman erilistä tietoa koodistosta, johon koodi kuuluu. Koodin tunnus on HTTP URI -muotoinen.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="elinkaari/vaat-alakoodi-maar" %}
Olkoon koodi ```A``` mikä tahansa hierarkkisen koodiston sisältämä koodi. Koodin ```A``` alakoodilla tarkoitetaan koodia, joka on hierakkiassa sijoitettu koodin ```A``` alle. Koodi voi olla useamman ylemmän tason koodin alakoodi vain mikäli ko. ylemmän tason koodit ovat alakoodisuhteessa keskenään.
{% include common/clause_end.html %}

Käytännössä tietyn koodin alakoodit voidaan tunnistaa vertaamalla niiden tunnuksia:

{% include common/clause_start.html type="req" id="elinkaari/vaat-alakoodi-tunnus" %}
Koodin ```A``` alakoodin ```B``` tunnus alkaa koodin ```A``` tunnuksella ja sisältää sen jälkeen yhden tai useamman merkin.
{% include common/clause_end.html %}

## Muutokset ja tietojen versionti
{% include common/clause_start.html type="req" id="elinkaari/vaat-pysyva-sisalto" %}
Kukin rakentamisen lupapäätöksen tai sen osien tallennusoperaatio tietovarastoon muodostaa uuden version tallennettavista tietokohteista, mikäli yksittäinen tietokohde on miltään osin muuttunut verrattuna sen edelliseen versioon. Myös muutokset niissä tietomallin tietokohteissa, joihin tallennettavasta tietokohteesta viitataan, lasketaan ko. tietokohteen muutoksiksi. Tallennetun tietokohteen version sisältö ei voi muuttua tallennuksen jälkeen, poislukien sen voimassaolon päättymiseen, seuraavaan versioon linkittämiseen ja elinkaaritilaan liittyvät attribuutit, joita tietovarasto itse päivittää sen tiettyjen elinkaaritapahtumien yhteydessä.
{% include common/clause_end.html %}

Näin taataan ulkoisten viittausten eheys, sillä kaikkien tietokohteiden paikalliset ja viittaustunnukset viittaavat aina vain tiettyn, sisällöllisesti muuttumattomaan versioon viittatusta kohteesta. Suositeltavaa on, että kaikki tallennusversiot myös pidetään pysyvästi tallessa, jotta mahdolliset keskenäiset ja ulkopuolelta tulevat linkit eivät mene rikki muutosten yhteydessä.

### Yksittäisen tietokohteen muutoshistoria
Tietomalli mahdollistaa tunnistettavien tietokohteiden eri kehitysversioiden erottamisen toisistaan. Kullakin tietomallin kohteella on sekä sen tosimaailman identiteettiin liittyvä ns. identiteettitunnus että yksittäisen tallennusversion tunnus (paikallinen tunnus). Tallennettaessa uutta versiota samasta tietokohteesta, sen identiteettitunnus pysyy ennallaan, mutta sen paikallinen tunnus muuttuu. Versioitavien objektien suhteen samuuden määritteleminen on tietoja tuottavien järjestelmien vastuulla: mikäli objektilla on tallennettavaksi lähetettäessä saman ```identititeettiTunnus```-attribuutin arvo kuin aiemmin tallennetulla, samantyyppisellä tietokohteella, katsotaan uusi objekti on saman tietokohteen uudeksi versioksi.

{% include common/clause_start.html type="req" id="elinkaari/vaat-version-korvaus" %}
Kun tietokohteesta tallennetaan uusi muuttunut versio, jonka on tarkoitus korvata ko. kohteen aiemmin tallennettu versio, tulee tietokohteen edellisen version ```korvattuObjektilla```-assosiaatio asettaa viittaamaan tietokohteen uuteen versioon. Uuden tietokohteen version ```korvaaObjektin```-assosiaatio puolestaan asetetaan viittaamaan tietokohteen edelliseen, korvattavaan versioon. Molempien kohteiden ```tallennusAika```-attribuutin arvoksi asetetaan ajanhetki, jolloin tallennus ja muutos tietovarastoon on tehty.
{% include common/clause_end.html %}

Yksittäisen tietokohteen yksityiskohtainen muutoshistoria tietovarastossa saadaan seuraavalla sen ```korvattuObjektilla```- ja ```korvaaObjektin```-assosiaatioita. 

Attribuutin ```viimeisinMuutos``` arvo kuvaa ajanhetkeä, jolloin ko. tietokohteeseen on tehty sisällöllinen muutos tiedontuottajan tietojärjestelmässä. Tiedontuottajan järjestelmän osalta ei vaadita tiukkaa versiontipolitiikkaa, eli ```paikallinenTunnus```-attribuutin päivittämistä jokaisen tietokohteen muutoksen johdosta. ```viimeisinMuutos```-attribuutin päivittämien riittää kuvaamaan tiedon todellisen muuttumisajankohdan.

{% include common/question.html content="Lupien jatko-ajat yms. luvan myöntämisen jälkeiset muutokset: onko ok päivittää RakennuskohteenToimenpide-luokan objektien attribuutteja miltään osin, vai pitääkö niistä tehdä aina uudet tallennusversiot? Olisi selkeä ratkaisu että lupapäätöksen tekemisen jälkeen ko. asiaan sisältyviä RakennuskohteenToimenpide-objekteja ei saa koskaan muuttaa. Hankkeen yhteydessä päivitetään ainoastaan ToimenpiteenTila-luokkaa, joka viittaa aina samaan luvan myöntämisaikaiseen versioon toimenpide-objektista. Tällöin jatkoaikatiedot pitää siirtää ToimenpiteenTila-luokkaan, ja jatkoajan myöntämisen tallennus tapahtuu päivittämällä Rakentamishanke-objektia. Pitäisikö toimenpiteelle myönnetty jatkoaika kuvata omana luokkanaan?" %}

## Lupaprosessin aikaiset muutokset

### Lupahakemusprosessin käynnistäminen
Varsinainen lupaprosessi alkaa tietomallin näkökulmasta joko rakentamisluvan jättämisestä, jolloin rakentamislupa-asia tulee suoraan vireille, tai rakennusvalvonnan ja luvan hakijan ennakkoneuvottelusta. Mikäli tietomallin avulla ei tueta lupahakemusprosessin kulkua, voidaan [RakentamislupaAsia](dokumentaatio/#rakentamislupaasia) ja siihen liitetyt [Rakentamislupahakemus](dokumentaatio/#rakentamislupahakemus)-luokan objektit luoda vasta luvan myöntämisen yhteydessä.

#### Rakentamislupa-asian synty

{% include common/clause_start.html type="req" id="elinkaari/vaat-lupa-asian-synty-ennakkoneuvottelulla" %}
Mikäli lupaprosessissa käydään ennakkoneuvottelu ennen lupahakemuksen jättämistä, ja sen tietoja halutaan kirjata tietomalliin, tulee luoda uusi [RakentamislupaAsia](dokumentaatio/#rakentamislupaasia)-luokan objekti attribuutin ```elinkaari``` arvolla ```Ennakkoneuvottelu```. Attribuutille ```virelletuloAika``` ei saa antaa arvoa.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="elinkaari/vaat-lupa-asian-synty-hakemuksella" %}
Mikäli lupaprosessin aikaisia tietoja halutaan kirjata tietomalliin lupahakemuksen jättämisen yhteydessä, mutta ennen lupapäätöksen tekemistä, tulee luvan jättämisvaiheessa luoda uusi [RakentamislupaAsia](dokumentaatio/#rakentamislupaasia)-luokan objekti attribuutin ```elinkaari``` arvolla ```Virellä```.

Luotavaan RakentamislupaAsia-luokan objektiin tulee liittää [Rakentamislupahakemus](dokumentaatio/#rakentamislupahakemus)-luokan objekti assosiaatiolla ```hakemus```, joka sisältää lupahakemuksen tiedot.

Luotavaan RakentamislupaAsia-luokan objektiin tulee liittää ainakin yksi abstraktin [RakennuskohteenToimenpide](dokumentaatio/#rakennuskohteentoimenpide)-luokan aliluokan objekti assosiaatiolla ```toimenpide```. Yhdessä kaikki ```toimenpide```-assosiaatioiden arvot kuvaavat ne rakentamis- ja purkamistoimenpiteet, joita koskevien lupien myöntämistä rakentamislupa-asiassa käsitellään.

RakentamislupaAsia-luokan objektin attribuutille ```virelletuloAika``` annetaan arvoksi lupahakemuksen vastaanottamisen aika.

RakentamislupaAsia-luokan objektin attribuutille ```aluerajaus``` arvoksi on annettava aluemainen tai monialuegeometria, joka sisältää kaikkien hakemuksella luvitettaviksi haluttujen toimenpiteiden rakennuspaikkojen sijannit.

Kukin lupahakemuksen liitetiedosto tulee kuvata RakentamislupaAsia-luokan objektin attribuutin ```asianLiite``` avulla, mukaanlukien hakemuksen mukana mahdollisesti toimitettavat BIM-suunnitelmamallit ja rakennussuunnitelmat.
{% include common/clause_end.html %}


#### Rakentamislupahakemuksen synty
{% include common/clause_start.html type="req" id="elinkaari/vaat-lupahakemuksen-synty" %}
[Rakentamislupahakemus](dokumentaatio/#rakentamislupahakemus)-luokan objekti syntyy luotaessa lupahakemuksen tiedot. Hakemukseen liitetyt rakennussuunnitelmat liitetään Rakentamislupahakemus-luokkaan sen assosiaation ```rakennussuunnitelma``` kautta ja mahdolliset BIM-suunnitelmamallit assosiaation ```suunnitelmamalli``` kautta.

Rakentamislupahakemus ja [RakentamislupaAsia](dokumentaatio/#rakentamislupaasia), johon se kuuluuu voidaan luoda tietojärjestelmään myös vasta luvan myöntämisen yhteydessä. 
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="elinkaari/vaat-lupahakemus-lupatyyppi" %}
Haettavan luvan tyyppi (sijoittamis- tai toteuttamislupa tai niiden yhdistelmä) tulee ilmaista [Rakentamislupahakemus](dokumentaatio/#rakentamislupahakemus)-luokan attribuutin ```lupatyyppi``` avulla. Haetun luvan tyypin ei tarvitse olla sama kuin lupaprosessin lopputuloksena mahdollisesti myönnetyn luvan tyypin.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="elinkaari/vaat-haetut-poikkeamiset" %}
Lupahakemuksessa tunnistetut rakentamistoimenpiteen toteuttamisen vaatimat vähäiset poikkeamiset {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/#alueidenkäyttöjarakentamismääräys" title="AlueidenkäyttöJaRakentamismääräys" %}-luokan avulla kuvatuista rakentamista koskevista määräyksistä kuvataan [Rakentamislupahakemus](dokumentaatio/#rakentamislupahakemus)-luokan perityn ```haettuPoikkeaminen```-attribuutin arvojen avulla.
{% include common/clause_end.html %}

Yhteen [RakentamislupaAsiaan](dokumentaatio/#rakentamislupaasia) voidaan liittää myös useampi kuin yksi [Rakentamislupahakemus](dokumentaatio/#rakentamislupahakemus). Esimerkiksi voidaan hakea ensin sijoitamislupaa ja täydentää sitä toteuttamislupahakemuksella. Lupa-asiassa voidaan tällöin tehdä päätös, jolla myönnetään vain yksi [Rakentamislupa](dokumentaatio/#rakentamislupa), jonka ```lupatyyppi``` on yhdistetty sijoittamis- ja toteuttamislupa. 

#### Rakennuskohteen toimenpiteen synty
{% include common/clause_start.html type="req" id="elinkaari/vaat-rakennuskohteen-toimepide-maaritelma" %}
RakennuskohteenToimenpide kuvaa toimenpiteen, joka kohdistuu yhden Rakennuskohteen rakentamiseen, korjaamiseen, laajentamiseen tai purkamiseen. Erikoistapauksena sama toimenpide voi kohdistua useampaan kuin yhteen Rakennuskohteeseen silloin, kun toimenpiteen johdosta yhdistetään useampia aiemmin erillisiä Rakennuskohteita yhdeksi tai kun pilkotaan yksi Rakennnuskohde useammaksi Rakennuskohteeksi.

Rakennuspaikat, joihin rakennuskohteen toimenpide kohdistuu, tulee liittää luotavaan objektiin assosiaation ```paikka``` avulla.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="elinkaari/vaat-rakennuskohteen-toimepide-synty-lupaprosessissa" %}
Luvanvaraisia toimenpiteitä kuvaavat [RakennuskohteenToimenpide](dokumentaatio/#rakennuskohteentoimenpide)-luokan alaluokkien objektit syntyvät samalla kun luodaan ensimmäinen kyseiseen lupa-asiaan liittyvä lupahakemus.

[RakentamislupaAsia](dokumentaatio/#rakentamislupaasia), johon toimenpide kuuluu, tulee liittää luotavaan objektiin assosiaation ```asia``` avulla.

RakennuskohteenToimenpide ja [RakentamislupaAsia](dokumentaatio/#rakentamislupaasia), johon se kuuluuu voidaan luoda tietojärjestelmään myös vasta luvan myöntämisen yhteydessä. 
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="elinkaari/vaat-rakennuskohteen-toimepide-synty-ilman-lupa-asiaa" %}
RakennuskohteenToimenpide-luokan avulla voidaan kuvata myös ei-luvanvaraisia toimenpiteitä. Tällöin assosiaatiota ```asia``` ei käytetä.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="elinkaari/vaat-toimenpiteen-kohde" %}
[RakennuskohteenToimenpide](dokumentaatio/#rakennuskohteentoimenpide)-luokan objektin on sisällettävä vähintään yksi [RakennuskohteenMuutos](dokumentaatio/#rakennuskohteenmuutos)-luokan kuvaama tietotyyppi attribuutin ```suunniteltuMuutos``` arvona.

RakennuskohteenMuutos-luokan assosiaation ```kohdeEnnenMuutosta``` tulee viitata {% include common/moduleLink.html moduleId="rakennuskohteet" path="looginenmalli/dokumentaatio/#rakennuskohde" title="Rakennuskohde" %}-luokan objektiin, johon suunniteltu muuutos kohdistuu. Mikäli kyseessä on uusi rakennuskohde (esim. uudisrakennus), ei assosiaatiota ```kohdeEnnenMuutosta``` käytetä.

RakennuskohteenMuutos-luokan assosiaation ```kohdeMuutoksenJälkeen``` tulee viitata {% include common/moduleLink.html moduleId="rakennuskohteet" path="looginenmalli/dokumentaatio/#rakennuskohde" title="Rakennuskohde" %}-luokan objektiin, joka kuvaa rakennuskohteen uutta tilaa suunnitellun muutoksen toteuttamisen jälkeen. Mikäli kyseessä on uusi rakennuskohde (esim. uudisrakennus), tulee tässä vaiheessa luoda uusi, suunniteltu rakennuskohdetta kuvaava Rakennuskohde-luokan objekti, johon assosiaatio viittaa.
{% include common/clause_end.html %}

### Hakemuksen käsittely ja luvan myöntäminen
Rakentamislupa-asiaan liittyviä tietoja voidaan muuttaa ja täydentää asian ollessa vireillä. Kun lupa-asiassa on tehty päätös, siihen kuuluvia tietoja ei voida enää muuttaa, poislukien mahdollisen valituksen johdosta tehty päätöksen kumoutuminen ennen sen tuloa lainvoimaiseksi.

{% include common/clause_start.html type="req" id="elinkaari/vaat-vireilla-olevan-asian-muutokset" %}
[RakentamislupaAsia](dokumentaatio/#rakentamislupaasia)-luokan objekteista ja niihin liitetyistä [Rakentamislupahakemus](dokumentaatio/#rakentamislupahakemus)- ja [RakennuskohteenToimenpide](dokumentaatio/#rakennuskohteentoimenpide)-luokkien objeista, ja edelleen niihin liittyvistä [Rakennuspaikka](dokumentaatio/#rakennuspaikka)-, {% include common/moduleLink.html moduleId="rakennuskohteet" path="looginenmalli/dokumentaatio/#rakennustietomalli" title="Rakennustietomalli" %}-, ja {% include common/moduleLink.html moduleId="rakennuskohteet" path="looginenmalli/dokumentaatio/#rakennussuunnitelma" title="Rakennussuunnitelma" %}-luokkien objekteista voidaan tehdä päivitettyjä versiota vain mikäli [RakentamislupaAsia](dokumentaatio/#rakentamislupaasia)-luokan objektin attribuutin ```elinkaaritila``` arvo on ```Vireillä```.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="elinkaari/vaat-rakennuslupa-asian-paatos" %}
Kun virellä olleessa rakentamislupa-asiassa tehdään päätös, vaihtuu sitä kuvaavan [RakentamislupaAsia](dokumentaatio/#rakentamislupaasia)-luokan objektin ```elinkaaritila```-attribuutin arvoksi ```Päätös annettu```. Itse päätöksen tiedot kuvataan luokan {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/#rakennetunympäristönlupapäätös" title="RakennetunYmpäristönLupapäätös" %}-luokan objektina, joka liitetään [RakentamislupaAsia](dokumentaatio/#rakentamislupaasia)-luokan objektiin assosiaation ```asia``` avulla. Vastaavasti päätös liitetään rakentamislupa-asiaan assosiaation ```päätös``` avulla.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="elinkaari/vaat-myonnetty-lupa" %}
Mikäli päätös rakentamislupa-asiassa tehdään myönteinen päätös, luodaan uusi [Rakentamislupa](dokumentaatio/#rakentamislupa)-luokan objekti, joka liitetään [RakentamislupaAsia](dokumentaatio/#rakentamislupaasia)-luokan objektiin ja {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/#rakennetunympäristönlupapäätös" title="RakennetunYmpäristönLupapäätös" %}-luokan objektiin niiden assosiaatioiden ```myönnettyLupa``` avulla. Vastaavasti luotu [Rakentamislupa](dokumentaatio/#rakentamislupa)-luokan objekti liitetään [RakentamislupaAsia](dokumentaatio/#rakentamislupaasia)-luokan objektiin ```asia```-asssosiaation ja {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/#rakennetunympäristönlupapäätös" title="RakennetunYmpäristönLupapäätös" %}-luokan objektiin ```myöntämispäätös```-assosiaation avulla.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="elinkaari/vaat-myonnetyt-poikkeamiset" %}
Lupapäätöksellä myönnetyt rakentamistoimenpiteen toteuttamisen vaatimat vähäiset poikkeamiset {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/#alueidenkäyttöjarakentamismääräys" title="AlueidenkäyttöJaRakentamismääräys" %}-luokan avulla kuvatuista rakentamista koskevista määräyksistä kuvataan [Rakentamislupa](dokumentaatio/#rakentamislupa)-luokan perityn ```myönnettyPoikkeaminen```-attribuutin arvojen avulla.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="elinkaari/vaat-lupamaaraykset" %}
Myönnettävään rakentamislupaan sisältyvät lupamääräykset kuvataan {% include common/moduleLink.html moduleId="yhteisetkomponentit" path="looginenmalli/dokumentaatio/#lupamääräys" title="Lupamääräys" %}-luokan objektien avulla, ja ne liitetään osaksi luotavaa [Rakentamislupa](dokumentaatio/#rakentamislupa)-luokan objektia sen assosiaation ```määräys``` avulla. Rakentamislupaan kuuluvien määräysten ```määräyksenLaji```-attribuutin arvon tulee olla koodiston [RakentamislupamääryksenLaji](dokumentaatio/#rakentamislupamääräyksenlaji) koodi.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="elinkaari/vaat-myonnetty-poikkeamislupa" %}
Mikäli rakentamisluvan myöntämiseen tarvitaan erillinen myönnetty poikkeamislupa, se liitetään luotavaan [Rakentamislupa](dokumentaatio/#rakentamislupa)-luokan objektiin assosiaation ```liitttyväLupa``` avulla.
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="elinkaari/vaat-kielteinen-lupapäätös" %}
TODO
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="elinkaari/vaat-peruutettu-hakemus" %}
TODO
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="elinkaari/vaat-lupapaatoksen-kumoutuminen" %}
TODO
{% include common/clause_end.html %}

{% include common/clause_start.html type="req" id="elinkaari/vaat-lupapaatoksen-tulo-lainvoimaiseksi" %}
TODO
{% include common/clause_end.html %}

## Rakentamishankkeen aikaiset muutokset

### Luvitetun rakentamistoimenpiteen jatkoaika

### Hankkeen aloittaminen

### Hankkeen aikaiset muutokset ja katselmukset

### Hankkeen valmistuminen

## Käyttöönoton jälkeiset muutokset




