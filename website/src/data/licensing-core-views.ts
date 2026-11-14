// The Licensing Core explorer on /protocol/: the same licenses, seen through
// RSL 1.0 and IAB CoMP 1.0. For each license in LicensingCore.astro's
// LICENSES, `rows[i]` says how the other standard expresses that license's
// clause `rows[i]`, and `file` is the declaration that says as much of the
// license as the standard can.
//
// Sources, pinned:
// - RSL 1.0: RSL-SPEC-1.0, "Status Recommendation ... Published 2025-12-10",
//   https://rslstandard.org/rsl, checked 2026-11-13.
// - CoMP 1.0: IABTechLab/CoMP CoMP-1.0.md at commit 880238e0 (blob aa8c796b),
//   the revision proto/comp/v1/comp.proto mirrors, checked 2026-11-13.
//
// Statuses compare each standard with the FORA term, clause by clause. The
// rule (decided 2026-11-13): a clause with no field is "linked" when the
// declaration links a document that carries it (RSL <standard> or <terms>,
// CoMP licenseurl), and "none" when nothing is linked or the gap is in the
// link itself (no digest). A field that points to the license for its value
// (CoMP max 1) is "differs".

export type Status = 'maps' | 'differs' | 'linked' | 'none';

export const STATUSES: Record<Status, { label: string; meaning: string }> = {
  maps: { label: 'Maps', meaning: 'A field or word in the standard says what the license clause says.' },
  differs: { label: 'Different meaning', meaning: 'The closest field or word has a narrower, wider or different meaning, or only flags that the license says more.' },
  linked: { label: 'Only in the linked text', meaning: 'No field says it, but a document the declaration links to does.' },
  none: { label: 'Not representable', meaning: 'No field says it, and the declaration links no document that does.' },
};

export type View = {
  file: string;
  rows: { status: Status; text: string }[];
  takeaway: string;
};

export type Standard = {
  id: 'rsl' | 'comp';
  name: string;
  fileLabel: string;
  intro: string;
  source: { label: string; href: string; pin?: string };
};

export const STANDARDS: Standard[] = [
  {
    id: 'rsl',
    name: 'RSL 1.0',
    fileLabel: 'license.xml',
    intro: 'Really Simple Licensing: an XML file the publisher hosts, telling crawlers and other automated clients what they may do with the content and what they owe for it.',
    source: { label: 'RSL 1.0 specification', href: 'https://rslstandard.org/rsl', pin: 'published 2025-12-10, errata through 2026-08-07' },
  },
  {
    id: 'comp',
    name: 'IAB CoMP 1.0',
    fileLabel: 'CoMP Package',
    intro: 'IAB Tech Lab\'s Content Monetization Protocols: the content owner answers an AI system\'s request with a package that describes the content, its price and where the license is. CoMP leaves the license terms to be negotiated beforehand.',
    source: {
      label: 'CoMP 1.0 specification',
      href: 'https://github.com/IABTechLab/CoMP/blob/880238e0100b3d0d67d5afd7357a18fc21a97be5/CoMP-1.0.md',
      pin: 'commit 880238e0',
    },
  },
];

const RSL_NS = 'xmlns="https://rslstandard.org/rsl"';

export const VIEWS: Record<string, Record<Standard['id'], View>> = {
  'cc-by': {
    rsl: {
      file: `<rsl ${RSL_NS}>
  <content url="/photos/harbor.jpg">
    <license>
      <permits type="usage">all</permits>
      <payment type="attribution">
        <standard>https://creativecommons.org/licenses/by/4.0/</standard>
      </payment>
      <legal type="disclaimer">as-is no-warranty</legal>
    </license>
  </content>
</rsl>`,
      rows: [
        { status: 'differs', text: '`all`, RSL\'s widest usage token, means "any automated processing", narrower than copying and sharing by people. Those rights come from the CC BY license that `<standard>` names.' },
        { status: 'linked', text: 'No token for adaptation. Remixing and building on the work rest on the CC BY license alone.' },
        { status: 'maps', text: 'No `<permits type="user">`, so any user, commercial or not.' },
        { status: 'maps', text: 'No `<permits type="geo">`, so worldwide. `attribution` asks for credit, not money.' },
        { status: 'maps', text: '`<payment type="attribution">` requires "visible credit and a functional link to the original source". Linking the license and noting changes are CC BY duties.' },
        { status: 'maps', text: 'RSL states the disclaimer in the XML: `<legal type="disclaimer">as-is no-warranty</legal>`.' },
      ],
      takeaway: 'The RSL specification uses CC BY as its own `<standard>` example. The credit and the disclaimer are in the XML; the rights to copy and adapt are in the license it names.',
    },
    comp: {
      file: `{
  "id": "harbor-photo",
  "seller": "photos.example",
  "licenseurl": "https://creativecommons.org/licenses/by/4.0/",
  "citation": 1,
  "scope": {
    "ause": 0,
    "pricetype": 3,
    "unitprice": 0,
    "cur": "USD",
    "ctype": [2],
    "image": [{ "title": ["Harbor at dawn"], "author": ["J. Doe"] }]
  }
}`,
      rows: [
        { status: 'linked', text: 'A package has no field for permitted functions. The AI system names its intended `function` in the request, and the license at `licenseurl` decides.' },
        { status: 'linked', text: 'No field for adaptation. Remixing rests on the CC BY text at `licenseurl`.' },
        { status: 'maps', text: '`ause` 0 (commercial) allows commercial use.' },
        { status: 'maps', text: 'CoMP has no free price type, so free is `pricetype` 3 (flat) at `unitprice` 0. No `country` is listed.' },
        { status: 'maps', text: '`citation` 1 says the content owner must be cited, and the image\'s `author` field names J. Doe. Linking the license and noting changes are CC BY duties.' },
        { status: 'linked', text: 'No warranty field. The disclaimer is in the CC BY text at `licenseurl`.' },
      ],
      takeaway: 'The package names CC BY, requires the credit and allows commercial use. The rights to copy and adapt, and the disclaimer, are in the license text.',
    },
  },

  'cc-by-nc-sa': {
    rsl: {
      file: `<rsl ${RSL_NS}>
  <content url="/photos/harbor.jpg">
    <license>
      <permits type="usage">all</permits>
      <permits type="user">non-commercial</permits>
      <payment type="attribution">
        <standard>https://creativecommons.org/licenses/by-nc-sa/4.0/</standard>
      </payment>
    </license>
  </content>
</rsl>`,
      rows: [
        { status: 'differs', text: '`all` means "any automated processing", narrower than copying and adapting by people. Those rights come from the CC BY-NC-SA license that `<standard>` names.' },
        { status: 'differs', text: '`<permits type="user">non-commercial</permits>` is a user class, defined as "Non-commercial purposes" and applied to "the entity or operational context responsible for the automated use". CC BY-NC-SA tests the purpose of each use.' },
        { status: 'linked', text: 'No share-alike element.' },
        { status: 'maps', text: '`<payment type="attribution">`: visible credit and a functional link.' },
        { status: 'maps', text: 'No `<permits type="geo">`, so worldwide. `attribution` asks for credit, not money.' },
        { status: 'linked', text: 'RSL defines `non-commercial` in three words, "Non-commercial purposes". The CC definition is in the license that `<standard>` names.' },
      ],
      takeaway: 'The credit and the license URL carry over, and share-alike travels with the URL. Non-commercial shifts meaning: RSL classifies the entity responsible for the use, CC tests the purpose of each use.',
    },
    comp: {
      file: `{
  "id": "harbor-photo-nc",
  "seller": "photos.example",
  "licenseurl": "https://creativecommons.org/licenses/by-nc-sa/4.0/",
  "citation": 1,
  "scope": {
    "ause": 1,
    "pricetype": 3,
    "unitprice": 0,
    "cur": "USD",
    "ctype": [2]
  }
}`,
      rows: [
        { status: 'linked', text: 'No field for permitted functions. Copying and adapting rest on the license at `licenseurl`.' },
        { status: 'maps', text: '`ause` 1 (non-commercial) states the kind of use allowed. CoMP gives the value a label and no definition.' },
        { status: 'linked', text: 'No share-alike field.' },
        { status: 'maps', text: '`citation` 1 says the content owner must be cited. How to credit, and the link to the license, are in the CC text.' },
        { status: 'maps', text: 'Free is `pricetype` 3 (flat) at `unitprice` 0. No `country` is listed.' },
        { status: 'linked', text: 'The CC definition of non-commercial is at `licenseurl`.' },
      ],
      takeaway: '`ause` 1 states non-commercial as a kind of use, as CC does. Share-alike exists only in the license text.',
    },
  },

  mit: {
    rsl: {
      file: `<rsl ${RSL_NS}>
  <content url="/code/parser.tar.gz">
    <license>
      <permits type="usage">all</permits>
      <payment type="free">
        <standard>https://opensource.org/license/mit</standard>
      </payment>
      <legal type="disclaimer">as-is no-warranty no-liability</legal>
    </license>
  </content>
</rsl>`,
      rows: [
        { status: 'differs', text: '`all` means "any automated processing", narrower than using, merging, selling and sublicensing. Those rights come from the MIT license that `<standard>` names.' },
        { status: 'maps', text: '`<payment type="free">` with no `<permits type="user">`: free, to anyone.' },
        { status: 'linked', text: 'No notice element. RSL\'s `attribution` is a credit and a link, not a notice kept in copies.' },
        { status: 'maps', text: 'RSL states the disclaimer in the XML: `<legal type="disclaimer">as-is no-warranty no-liability</legal>`.' },
      ],
      takeaway: 'The XML says free, to anyone, as is. The grant itself and the notice duty are in the MIT text that `<standard>` names.',
    },
    comp: {
      file: `{
  "id": "parser-source",
  "seller": "code.example",
  "licenseurl": "https://opensource.org/license/mit",
  "citation": 0,
  "scope": {
    "ause": 0,
    "pricetype": 3,
    "unitprice": 0,
    "cur": "USD",
    "ctype": [0]
  }
}`,
      rows: [
        { status: 'linked', text: 'No field for permitted functions. Using, merging, selling and sublicensing rest on the MIT text at `licenseurl`.' },
        { status: 'maps', text: 'Free is `pricetype` 3 (flat) at `unitprice` 0. A package has no field that limits who may use it.' },
        { status: 'linked', text: 'No notice field. `citation` is about citing the content owner, not keeping a notice in copies, and this package sets it to 0.' },
        { status: 'linked', text: 'No warranty field. The disclaimer is in the MIT text at `licenseurl`.' },
      ],
      takeaway: 'The fields say free, for commercial use. The grant, the notice and the disclaimer are all at `licenseurl`.',
    },
  },

  agpl: {
    rsl: {
      file: `<rsl ${RSL_NS}>
  <content url="/code/server.tar.gz">
    <license>
      <permits type="usage">all</permits>
      <payment type="free">
        <standard>https://www.gnu.org/licenses/agpl-3.0.html</standard>
      </payment>
    </license>
  </content>
</rsl>`,
      rows: [
        { status: 'differs', text: '`all` means "any automated processing", narrower than running, studying, modifying and sharing. Those rights come from the AGPL that `<standard>` names.' },
        { status: 'linked', text: 'No share-alike element.' },
        { status: 'linked', text: 'No element for software offered over a network.' },
        { status: 'linked', text: 'No notice element.' },
        { status: 'linked', text: 'No element for a patent grant or termination.' },
      ],
      takeaway: 'The XML names the AGPL and marks it free. The copyleft, the network clause and the notices exist only in the license it names.',
    },
    comp: {
      file: `{
  "id": "server-source",
  "seller": "code.example",
  "licenseurl": "https://www.gnu.org/licenses/agpl-3.0.html",
  "scope": {
    "ause": 0,
    "pricetype": 3,
    "unitprice": 0,
    "cur": "USD",
    "ctype": [0]
  }
}`,
      rows: [
        { status: 'linked', text: 'No field for permitted functions. Running, studying, modifying and sharing rest on the AGPL at `licenseurl`.' },
        { status: 'linked', text: 'No share-alike field.' },
        { status: 'linked', text: 'No field for software offered over a network.' },
        { status: 'linked', text: 'No notice field.' },
        { status: 'linked', text: 'No field for a patent grant or termination.' },
      ],
      takeaway: 'As in RSL, the package names the AGPL and prices it at zero. Every duty the AGPL imposes stays in its text.',
    },
  },

  rsl: {
    rsl: {
      file: `<rsl ${RSL_NS}>
  <content url="/articles/">
    <license>
      <permits type="usage">ai-input search</permits>
      <prohibits type="usage">ai-train</prohibits>
      <payment type="crawl">
        <amount currency="USD">0.05</amount>
      </payment>
    </license>
  </content>
</rsl>`,
      rows: [
        { status: 'maps', text: '`<permits type="usage">ai-input search</permits>`. FORA registers RSL\'s six usage tokens unchanged.' },
        { status: 'maps', text: '`<prohibits type="usage">ai-train</prohibits>`.' },
        { status: 'maps', text: '`<payment type="crawl">` with `<amount>`: a payment "every time the content is crawled".' },
        { status: 'none', text: 'A license has one `<payment>` with one type, and `attribution` is a type. A license priced per crawl can\'t also require credit in the XML.' },
      ],
      takeaway: 'This is the kind of license RSL was designed for, and three of its four clauses map. The credit is lost because RSL makes `attribution` a payment type, and the one payment here is the crawl fee.',
    },
    comp: {
      file: `{
  "id": "articles-ai",
  "seller": "news.example",
  "licenseurl": "https://news.example/license.xml",
  "citation": 1,
  "scope": {
    "scope": 1,
    "pricetype": 0,
    "unitprice": 0.05,
    "cur": "USD",
    "ctype": [0]
  }
}`,
      rows: [
        { status: 'linked', text: 'No field for permitted functions. `function`, with the same `ai-input` and `search` values, is what the AI system declares in its request; the license decides.' },
        { status: 'linked', text: 'No field prohibits a function. The ban on `ai-train` is in the license at `licenseurl`.' },
        { status: 'differs', text: '`pricetype` 0 (per use) at `unitprice` 0.05. CoMP doesn\'t define one use, so a price per fetch and a price per answer read the same.' },
        { status: 'maps', text: '`citation` 1 beside a per-use price: CoMP can require credit on paid content.' },
      ],
      takeaway: 'CoMP keeps the credit RSL loses, because `citation` is a field of its own. Which functions are allowed or banned stays in the license.',
    },
  },

  subscription: {
    rsl: {
      file: `<rsl ${RSL_NS}>
  <content url="/archive/">
    <license>
      <permits type="usage">ai-input ai-index</permits>
      <prohibits type="usage">ai-train</prohibits>
      <payment type="subscription">
        <custom>https://news.example/licensing/ai</custom>
      </payment>
      <reporting type="audit"
                 profile="https://news.example/licensing/ai/reporting/v1"
                 endpoint="https://news.example/licensing/ai/reports"/>
    </license>
    <terms>https://news.example/licensing/ai/terms</terms>
  </content>
</rsl>`,
      rows: [
        { status: 'differs', text: 'No field names a licensee. `<custom>` sends agents to the licensing page, or a License Server (the `server` attribute) issues the license to each client. The public file can state the offer, not one subscriber\'s terms.' },
        { status: 'maps', text: '`subscription` is "Recurring payment for access". The file states no `<amount>`, so the fee stays private.' },
        { status: 'maps', text: '`<permits type="usage">ai-input ai-index</permits>` and `<prohibits type="usage">ai-train</prohibits>`.' },
        { status: 'linked', text: 'No quota element for a monthly cap.' },
        { status: 'differs', text: '`<reporting type="audit">` requires reports under a profile you publish. The 30-day window and the required fields are defined in that profile.' },
        { status: 'linked', text: '`<terms>` links the general subscription terms, with no digest to pin them. Terms negotiated with one subscriber stay out of the public file.' },
      ],
      takeaway: 'The payment type and the uses map, and reporting is required, with its window and fields in a profile. The licensee and the cap aren\'t in the file.',
    },
    comp: {
      file: `{
  "id": "acme-ai-2027-archive",
  "seller": "news.example",
  "licenseurl": "https://news.example/deals/acme-ai-2027.pdf",
  "reporturl": "https://news.example/deals/reports",
  "scope": {
    "scope": 0,
    "ause": 0,
    "pricetype": 3,
    "licensedur": 365,
    "max": 1,
    "ctype": [0]
  }
}`,
      rows: [
        { status: 'differs', text: 'No package field names the buyer. The AI system\'s request carries `lid`, the license ID it holds from the deal.' },
        { status: 'differs', text: '`pricetype` 3 (flat) with `licensedur` 365. The package states no `unitprice`, so the fee stays private.' },
        { status: 'linked', text: 'No field for permitted or prohibited functions.' },
        { status: 'differs', text: '`max` 1 says a limit exists. CoMP defines it as a limit on crawling and sends the AI system to the license for the figure.' },
        { status: 'differs', text: '`reporturl` says where to send reports. CoMP lists reporting as out of scope, so it has no field for the window or the report contents.' },
        { status: 'linked', text: 'No field for liability, audit rights or renewal.' },
      ],
      takeaway: '`max` and `reporturl` show that a cap and a reporting duty exist. Their size, window and contents are in the deal document at `licenseurl`.',
    },
  },

  stock: {
    rsl: {
      file: `<rsl ${RSL_NS}>
  <content url="/photos/7781.jpg">
    <!-- No RSL words for display, print or advertising -->
    <license>
      <prohibits type="usage">ai-all</prohibits>
      <payment type="purchase">
        <amount currency="USD">29.00</amount>
      </payment>
    </license>
    <terms>https://stock.example/license/standard</terms>
  </content>
</rsl>`,
      rows: [
        { status: 'linked', text: 'RSL\'s usage tokens cover automated processing, and none means display, print or advertising. `<prohibits type="usage">ai-all</prohibits>` rules out AI use; other automated processing, such as `search`, stays permitted.' },
        { status: 'linked', text: 'No token for selling the image as a product.' },
        { status: 'linked', text: 'No quota element for a print run.' },
        { status: 'maps', text: '`<payment type="purchase">`, a one-time payment, with `<amount>`. No `<permits type="geo">`, so worldwide.' },
        { status: 'linked', text: '`<terms>` links the license text, with no digest to pin it.' },
      ],
      takeaway: 'The price maps, and `ai-all` keeps AI systems out. The uses, the ban on merchandise and the print run are only in the license that `<terms>` links.',
    },
    comp: {
      file: `{
  "id": "stock-7781",
  "seller": "stock.example",
  "licenseurl": "https://stock.example/license/standard",
  "scope": {
    "ause": 0,
    "pricetype": 3,
    "unitprice": 29.0,
    "cur": "USD",
    "max": 1,
    "ctype": [2],
    "image": [{ "title": ["Harbor crane at dusk"] }]
  }
}`,
      rows: [
        { status: 'linked', text: 'No field for permitted functions. CoMP\'s `function` list, like RSL\'s usage tokens, covers automated processing.' },
        { status: 'linked', text: 'No field prohibits a use.' },
        { status: 'differs', text: '`max` 1 says a limit exists. CoMP defines it as a limit on crawling and sends the AI system to the license for the figure. Here the limit is on printed copies.' },
        { status: 'maps', text: '`pricetype` 3 (flat) at `unitprice` 29, with no `licensedur` and no `country` list.' },
        { status: 'linked', text: 'No field for trademark or sensitive-subject rules.' },
      ],
      takeaway: 'The package carries the price and says a limit exists. What the buyer may do with the photo, and how many copies, are in the license.',
    },
  },

  editorial: {
    rsl: {
      file: `<rsl ${RSL_NS}>
  <content url="/photos/summit-0412.jpg">
    <!-- No RSL words for editorial use or for news organizations -->
    <license>
      <prohibits type="usage">ai-all</prohibits>
      <payment type="purchase">
        <amount currency="USD">150.00</amount>
      </payment>
    </license>
    <copyright type="organization">Example Agency</copyright>
    <terms>https://photos.example/license/editorial</terms>
  </content>
</rsl>`,
      rows: [
        { status: 'linked', text: 'No usage token for editorial use. `<prohibits type="usage">ai-all</prohibits>` rules out AI use; other automated processing stays permitted.' },
        { status: 'linked', text: 'No token for advertising or merchandise, and `<permits type="user">non-commercial</permits>` would shut out the news organizations this license is for.' },
        { status: 'linked', text: 'RSL\'s user tokens are `commercial`, `non-commercial`, `education`, `government` and `personal`. None means a news organization.' },
        { status: 'differs', text: '`<copyright>` names Example Agency as the rights holder but imposes no duty to credit. The license\'s one `<payment>` is the purchase, so `attribution` can\'t be added.' },
        { status: 'linked', text: '`purchase` is a one-time payment, and RSL has no element for a term.' },
      ],
      takeaway: 'The price and the rights holder are in the XML, and `ai-all` keeps AI systems out. The editorial use, the news-only licensee, the credit line and the one-year term are only in the license that `<terms>` links.',
    },
    comp: {
      file: `{
  "id": "summit-0412",
  "seller": "photos.example",
  "licenseurl": "https://photos.example/license/editorial",
  "citation": 1,
  "scope": {
    "pricetype": 3,
    "unitprice": 150.0,
    "cur": "USD",
    "licensedur": 365,
    "ctype": [2],
    "image": [{ "title": ["Summit arrivals"], "author": ["J. Doe / Example Agency"] }]
  }
}`,
      rows: [
        { status: 'linked', text: 'No field for permitted functions.' },
        { status: 'linked', text: 'No field prohibits a use. `ause` 1 (non-commercial) is a different restriction from "no advertising or merchandise".' },
        { status: 'linked', text: '`ause` takes one value: commercial, non-commercial, educational, government, personal, BYO License or other. None names news organizations, and "other" would say nothing, so the package omits `ause`.' },
        { status: 'maps', text: '`citation` 1, and the image\'s `author` field carries the credit "J. Doe / Example Agency".' },
        { status: 'maps', text: '`licensedur` 365: the license runs 365 days from delivery.' },
      ],
      takeaway: 'CoMP states the credit line and the one-year term in fields, where RSL leaves both to the linked license. Editorial use and the news-only licensee stay in the license.',
    },
  },

  sync: {
    rsl: {
      file: `<rsl ${RSL_NS}>
  <content url="/tracks/harbor-lights.wav">
    <!-- No RSL words for sync, broadcast or streaming -->
    <license>
      <prohibits type="usage">ai-all</prohibits>
      <permits type="user">commercial</permits>
      <permits type="geo">GB IE</permits>
      <payment type="purchase">
        <amount currency="EUR">450.00</amount>
      </payment>
    </license>
    <copyright type="organization">Example Records</copyright>
    <terms>https://label.example/licenses/sync-tv.pdf</terms>
  </content>
</rsl>`,
      rows: [
        { status: 'linked', text: 'No usage token for sync, broadcast or streaming. RSL\'s usage tokens cover automated processing.' },
        { status: 'differs', text: '`<prohibits type="usage">ai-all</prohibits>` rules out AI training and every other AI use, wider than the clause. No token means advertising.' },
        { status: 'differs', text: '`<permits type="user">commercial</permits>` covers the production company. No user token means a broadcaster.' },
        { status: 'maps', text: '`<permits type="geo">GB IE</permits>`, in ISO 3166-1 alpha-2 codes, as FORA writes them.' },
        { status: 'linked', text: '`purchase` is a one-time payment, and RSL has no element for a term.' },
        { status: 'linked', text: 'No quota element for a count of productions.' },
        { status: 'linked', text: 'No element for a cue sheet.' },
        { status: 'differs', text: '`<copyright>` names the rights holder but imposes no duty to show the ℗ line.' },
        { status: 'linked', text: 'No element for these terms. RSL calls the `<terms>` document "supplemental legal information", not the authority a `REFERENCE_ONLY` term makes it.' },
      ],
      takeaway: 'The territory maps, and `<copyright>` names the label. Sync, the three-year term, the production limit and the cue sheet are only in the document that `<terms>` links.',
    },
    comp: {
      file: `{
  "id": "harbor-lights-sync",
  "seller": "label.example",
  "licenseurl": "https://label.example/licenses/sync-tv.pdf",
  "citation": 1,
  "scope": {
    "ause": 0,
    "pricetype": 3,
    "unitprice": 450.0,
    "cur": "EUR",
    "country": [826, 372],
    "licensedur": 1095,
    "max": 1,
    "ctype": [3],
    "audio": [{ "title": ["Harbor Lights"], "author": ["Example Records"] }]
  }
}`,
      rows: [
        { status: 'linked', text: 'No field for permitted functions. CoMP\'s `function` list, like RSL\'s usage tokens, covers automated processing.' },
        { status: 'linked', text: 'No field prohibits a use.' },
        { status: 'differs', text: '`ause` 0 (commercial) fits the production company. No `ause` value means a broadcaster.' },
        { status: 'maps', text: '`country` 826 and 372, the numeric codes for the United Kingdom and Ireland. The spec types `country` as integers and describes alpha-2 codes; this package follows the type.' },
        { status: 'maps', text: '`licensedur` 1095: three years, counted in days from delivery.' },
        { status: 'differs', text: '`max` 1 says a limit exists. CoMP defines it as a limit on crawling and sends the AI system to the license for the figure. Here the limit is on productions.' },
        { status: 'linked', text: 'No field for a cue sheet.' },
        { status: 'differs', text: '`citation` 1, with Example Records in the audio\'s `author` field. The ℗ line is in the document.' },
        { status: 'differs', text: '`licenseurl` links the document. `ause` 5 (BYO License) would refer the AI system to its terms, but `ause` holds one value, and this package uses it for commercial.' },
      ],
      takeaway: 'Territory and term are fields. The uses, the production limit and the cue sheet are in the document at `licenseurl`.',
    },
  },

  blanket: {
    rsl: {
      file: `<rsl ${RSL_NS}>
  <content url="/catalog/">
    <license>
      <payment type="purchase">
        <standard>https://society.example/license/MR-7741</standard>
        <amount currency="USD">500.00</amount>
      </payment>
    </license>
  </content>
</rsl>`,
      rows: [
        { status: 'maps', text: '`<standard>` names the society\'s license. A client that accepts it gains access to all content whose RSL licenses name the same URL.' },
        { status: 'none', text: 'RSL has no digest, so the document at the URL can change after the agent agrees to it.' },
        { status: 'maps', text: '`<payment type="purchase">` with `<amount>`.' },
        { status: 'differs', text: 'The XML restricts no use and leaves that to the society\'s document. RSL considers "only licensing terms defined in the RSL namespace" and has no rule for a conflict with the document that `<standard>` names.' },
      ],
      takeaway: 'RSL built `<standard>` for shared frameworks like this one: accept it once, and every file naming the URL is covered. RSL can\'t pin which version of the document the agent accepted.',
    },
    comp: {
      file: `{
  "id": "society-mr-7741",
  "seller": "society.example",
  "licenseurl": "https://society.example/license/MR-7741",
  "scope": {
    "ause": 5,
    "pricetype": 3,
    "unitprice": 500.0,
    "cur": "USD"
  }
}`,
      rows: [
        { status: 'maps', text: '`ause` 5 (BYO License): the terms are the ones at `licenseurl`.' },
        { status: 'none', text: '`licenseurl` has no digest, so the document can change after the agent agrees to it.' },
        { status: 'maps', text: '`pricetype` 3 (flat) at `unitprice` 500.' },
        { status: 'none', text: 'The package states only the license and the price, and CoMP has no rule for a field that contradicts the license.' },
      ],
      takeaway: '`ause` 5 is CoMP\'s value for this case. Like RSL, CoMP can\'t pin the document.',
    },
  },

  dataset: {
    rsl: {
      file: `<rsl ${RSL_NS}>
  <content url="/datasets/coastal-survey/">
    <license>
      <permits type="usage">ai-train ai-input</permits>
      <permits type="user">education non-commercial</permits>
      <payment type="subscription">
        <custom>https://data.example/institutions/join</custom>
      </payment>
    </license>
    <terms>https://data.example/license/institutional</terms>
  </content>
</rsl>`,
      rows: [
        { status: 'differs', text: '`<payment type="subscription">` with `<custom>`: your licensing page decides who subscribes.' },
        { status: 'maps', text: '`<permits type="usage">ai-train ai-input</permits>`.' },
        { status: 'differs', text: '`<permits type="user">education non-commercial</permits>`. `education` means "Educational use in schools or universities"; `non-commercial` is the nearest token to a non-profit, and names a purpose, not a kind of organization.' },
        { status: 'linked', text: 'No quota element for seats.' },
        { status: 'linked', text: 'No share-alike element. `<standard>` would name the dataset\'s license, not the one for trained models.' },
      ],
      takeaway: 'The AI uses map token for token, and the user list comes close. The ten-seat limit and the share-alike duty on trained models are only in the license that `<terms>` links.',
    },
    comp: {
      file: `{
  "id": "coastal-survey",
  "seller": "data.example",
  "licenseurl": "https://data.example/license/institutional",
  "scope": {
    "scope": 0,
    "ause": 2,
    "pricetype": 3,
    "unitprice": 0,
    "max": 1,
    "ctype": [0]
  }
}`,
      rows: [
        { status: 'differs', text: 'No package field names the buyer. The AI system\'s request carries `lid`, the license ID it holds from its subscription.' },
        { status: 'linked', text: 'No field for permitted functions.' },
        { status: 'differs', text: '`ause` takes one value, here 2 (educational), so non-profit use can\'t be added beside it.' },
        { status: 'differs', text: '`max` 1 says a limit exists. CoMP defines it as a limit on crawling and sends the AI system to the license for the figure. Here the limit is on seats.' },
        { status: 'linked', text: 'No share-alike field.' },
      ],
      takeaway: 'One `ause` value, educational, stands in for two kinds of user. The seat limit is flagged; the AI uses and the duty on trained models are left to the license.',
    },
  },

  design: {
    rsl: {
      file: `<rsl ${RSL_NS}>
  <content url="/parts/bracket-v3.step">
    <!-- No RSL word for manufacturing -->
    <license>
      <prohibits type="usage">ai-all</prohibits>
      <payment type="purchase">
        <amount currency="USD">200.00</amount>
      </payment>
      <reporting type="audit"
                 profile="https://parts.example/reporting/production-runs"/>
    </license>
    <terms>https://parts.example/license/manufacture</terms>
  </content>
</rsl>`,
      rows: [
        { status: 'linked', text: 'No usage token for manufacturing; RSL\'s usage tokens cover automated processing. `<prohibits type="usage">ai-all</prohibits>` rules out AI use.' },
        { status: 'linked', text: 'No quota element for a unit count.' },
        { status: 'differs', text: '`<reporting type="audit">` requires "periodic or aggregate compliance reporting" under a profile you publish.' },
        { status: 'linked', text: '`contribution` is a payment type, and the license\'s one `<payment>` is the purchase. RSL calls a second `<license>` a distinct term set, so it would not add to the first.' },
      ],
      takeaway: 'The fee and the reporting duty have an RSL form. Manufacturing, the 1,000-unit cap and the royalty above it are only in the license that `<terms>` links.',
    },
    comp: {
      file: `{
  "id": "bracket-v3",
  "seller": "parts.example",
  "licenseurl": "https://parts.example/license/manufacture",
  "reporturl": "https://parts.example/reports",
  "scope": {
    "ause": 0,
    "pricetype": 3,
    "unitprice": 200.0,
    "cur": "USD",
    "max": 1,
    "ctype": [5]
  }
}`,
      rows: [
        { status: 'linked', text: 'No field for permitted functions. CoMP\'s `function` list, like RSL\'s usage tokens, covers automated processing.' },
        { status: 'differs', text: '`max` 1 says a limit exists. CoMP defines it as a limit on crawling and sends the AI system to the license for the figure. Here the limit is on units made.' },
        { status: 'differs', text: '`reporturl` says where to send reports. What to report, and when, is in the license.' },
        { status: 'linked', text: 'A package has one `pricetype` and one `unitprice`. `pricetype` 4 (tiered) carries only a tier identifier in `pricetier`, and no field holds a royalty.' },
      ],
      takeaway: 'The package carries the price, a reporting address and a limit flag. Manufacturing and the royalty are in the license; CoMP describes content offered to AI systems.',
    },
  },
};
