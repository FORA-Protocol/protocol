// The evidence behind /resources/transparent-collective/ ("A fair licensing
// collective"): every factual claim the article makes, the verbatim quote that
// supports it and its source. Rendered at
// /resources/transparent-collective/evidence/. Each claim id is an anchor, so
// the article can link to #<id>. Groups follow the article's sections.
//
// Kinds: 'primary' (the source itself says it, FORA's own docs and spec
// included), 'reported' (press or another third party), 'reading' (an
// inference drawn from the sources, an absence, or how a collective on FORA
// is meant to work; the reasoning is in note).
//
// Quotes are copied from the saved source text and checked by script against
// it. Non-English quotes are given in the original, with a translation in the
// note. Two documents ILC shows publishers in its portal have no public URL, so
// they are cited by section. Links go to readable pages, never to a commit.

export type EvidenceKind = 'primary' | 'reported' | 'reading';

export interface EvidenceSource {
  title: string;
  by: string;
  url?: string;
  /** Section, paragraph, clause or field, where there is one. */
  locator?: string;
}

export interface EvidenceClaim {
  /** Anchor id, unique on the page. */
  id: string;
  claim: string;
  /** Verbatim; " … " joins separate passages of the same source. None on an
   *  absence or a status statement, where no passage says it. */
  quote?: string;
  source: EvidenceSource;
  kind: EvidenceKind;
  note?: string;
  /** Subheading inside a group, where the group has parts. */
  topic?: string;
}

export interface EvidenceGroup {
  id: string;
  title: string;
  claims: EvidenceClaim[];
}

/** When the sources were checked, for the page's intro line. */
export const EVIDENCE_CHECKED = 'November 2026';

type Src = Omit<EvidenceSource, 'locator'>;

const S = {
  // ILC
  ilcPress: { title: 'The Internet Licensing Collective (ILC) Launches with Yahoo Scout as First Commercial Partner (press release)', by: 'Internet Licensing Collective', url: 'https://internetcollective.org/press/ilc-launch-2026' },
  ilcFaq: { title: 'Frequently asked questions', by: 'Internet Licensing Collective', url: 'https://internetcollective.org/faq' },
  ilcPublishers: { title: 'For publishers', by: 'Internet Licensing Collective', url: 'https://internetcollective.org/publishers' },
  ilcGuide: { title: 'Publisher Onboarding Guide', by: 'Internet Licensing Collective', url: 'https://internetcollective.org/docs/publishers/onboard' },
  ppa: { title: 'Publisher Participation Agreement, version 1.0, shown in ILC\'s publisher portal', by: 'Internet Licensing Collective' },
  policy: { title: 'ILC Royalty Distribution Policy, shown in ILC\'s publisher portal', by: 'Internet Licensing Collective' },
  portal: { title: 'ILC publisher portal, website verification check', by: 'Internet Licensing Collective' },
  // ProRata / Gist
  prMsa: { title: 'ProRata Online Master Services Agreement (MSA)', by: 'ProRata.ai', url: 'https://gist.ai/support/ga/wpnewpartner' },
  prPublishers: { title: 'For publishers and creators', by: 'ProRata.ai', url: 'https://prorata.ai/solutions/publishers-and-creators' },
  prAnswers: { title: 'Gist Answers', by: 'ProRata.ai', url: 'https://gist.ai/products/gist-answers' },
  prHow: { title: 'How it works', by: 'ProRata.ai', url: 'https://prorata.ai/how-it-works' },
  prDpcmo: { title: 'ProRata partners with DPCMO to launch the first decentralized sovereign AI answer engine', by: 'DPCMO', url: 'https://dpcmo.dk/2025/12/10/prorata-partners-with-dpcmo-to-launch-the-first-decentralized-sovereign-ai-answer-engine/' },
  // Perplexity
  comet: { title: 'Introducing Comet Plus', by: 'Perplexity', url: 'https://www.perplexity.ai/hub/blog/introducing-comet-plus' },
  cometPartners: { title: 'Announcing Comet Plus launch partners', by: 'Perplexity', url: 'https://www.perplexity.ai/hub/blog/announcing-comet-plus-launch-partners' },
  pplxPricing: { title: 'Pricing', by: 'Perplexity', url: 'https://www.perplexity.ai/hub/pricing' },
  pplxGannett: { title: 'Welcoming Gannett to the Perplexity Publisher Program', by: 'Perplexity', url: 'https://www.perplexity.ai/hub/blog/welcoming-gannett-to-the-perplexity-publisher-program' },
  pplxDigiday: { title: 'How Perplexity\'s new revenue model works, according to its head of publisher partnerships', by: 'Digiday', url: 'https://digiday.com/media/how-perplexity-new-revenue-model-works-according-to-its-head-of-publisher-partnerships/' },
  cnnSuit: { title: 'CNN Sues Perplexity for Unlawfully Distributing News Content', by: 'TheWrap', url: 'https://www.thewrap.com/industry-news/public-policy-legal/cnn-sues-perplexity-ai-stealing-news-chatbot-copyright/' },
  // CCC
  cccSheet: { title: 'AI Systems Training License: overview sheet', by: 'Copyright Clearance Center', url: 'https://www.copyright.com/wp-content/uploads/2026/03/AISTL-Overview-Sheet.pdf' },
  cccFrankfurt: { title: 'Frankfurt Book Fair 2025 press release', by: 'Copyright Clearance Center', url: 'https://www.copyright.com/wp-content/uploads/2025/10/2025-Frankfurt-Book-Fair-Press-Release.pdf' },
  cccMassDig: { title: 'Comment to the US Copyright Office on mass digitization', by: 'Copyright Clearance Center', url: 'https://www.copyright.gov/policy/massdigitization/comments/Copyright%20Clearance%20Center%20CCC.pdf' },
  cccPress: { title: 'CCC launching new AI content re-use rights for US academic customers and transactional licensing capabilities for AI', by: 'Copyright Clearance Center', url: 'https://www.copyright.com/media-press-releases/ccc-launching-new-ai-content-re-use-rights-for-u-s-academic-customers-and-transactional-licensing-capabilities-for-ai/' },
  cccTracker: { title: 'CCC AI Licensing Suite', by: 'datalicenses.org (tracker)', url: 'https://datalicenses.org/initiatives/ccc-ai-licensing-suite/' },
  // CLA, PLS, ALCS
  plsNews: { title: 'PLS offers new collective AI licensing opportunity to publishers', by: 'Publishers\' Licensing Services', url: 'https://www.pls.org.uk/news-events-policy/news/pls-offers-new-collective-ai-licensing-opportunity-to-publishers/' },
  plsCharter: { title: 'Distribution Charter', by: 'Publishers\' Licensing Services', url: 'https://www.pls.org.uk/distribution-charter/' },
  plsFlyer: { title: 'PLS opt-in licences: flyer', by: 'Publishers\' Licensing Services', url: 'https://www.pls.org.uk/media/2425/pls-opt-in-licences_flyer_sept26-digital.pdf' },
  plsReport: { title: 'Annual transparency report 2025–26', by: 'Publishers\' Licensing Services', url: 'https://www.pls.org.uk/media/2389/annual-transparency-report-2025-26.pdf' },
  plsTerms: { title: 'Terms and conditions', by: 'Publishers\' Licensing Services', url: 'https://www.pls.org.uk/terms-and-conditions/' },
  plsGov: { title: 'Governance', by: 'Publishers\' Licensing Services', url: 'https://www.pls.org.uk/about-pls/governance/' },
  plsArea: { title: 'Opt in to generative AI licensing (publisher area)', by: 'Publishers\' Licensing Services', url: 'https://www.pls.org.uk/publisher-area/opt-in-to-generative-ai-licensing/' },
  claReport: { title: 'Annual transparency report 2025', by: 'Copyright Licensing Agency', url: 'https://assets.cla.co.uk/media/2025/10/annual-transparency-report-2025.pdf' },
  // DPCMO
  dpReport: { title: 'Gennemsigtighedsrapport 2025 (transparency report, in Danish)', by: 'DPCMO', url: 'https://dpcmo.dk/wp-content/uploads/2026/06/Gennemsigtighedsrapport-2025-1.pdf' },
  dpStatutes: { title: 'Vedtægter (statutes, in Danish)', by: 'DPCMO', url: 'https://dpcmo.dk/wp-content/uploads/2024/07/Vedtaegter_20240523.pdf' },
  dpApproved: { title: 'Godkendt af Kulturministeriet (approved by the Ministry of Culture, in Danish)', by: 'DPCMO', url: 'https://dpcmo.dk/godkendt-af-kulturministeriet/' },
  dpHome: { title: 'DPCMO (home page, in Danish)', by: 'DPCMO', url: 'https://dpcmo.dk/' },
  dpOpenai: { title: 'A united Danish media industry takes OpenAI to court', by: 'DPCMO', url: 'https://dpcmo.dk/2026/02/27/a-united-danish-media-industry-takes-openai-to-court/' },
  // Kopinor
  koAgreement: { title: 'Agreement on the use of copyright-protected material in the training of Norwegian language models', by: 'Kopinor and the National Library of Norway', url: 'https://kopinor.no/wp-content/uploads/2026/02/Agreement-on-the-use-of-copyright-protected-material-in-the-training-of-Norwegian-language-models.pdf' },
  koPayout: { title: 'Kopinors største utbetaling noensinne (Kopinor\'s largest payout ever, in Norwegian)', by: 'Kopinor, via NTB', url: 'https://kommunikasjon.ntb.no/pressemelding/19066576/kopinors-storste-utbetaling-noensinne?publisherId=17848361' },
  koAnnual: { title: 'Årsmelding 2025 (annual report, in Norwegian)', by: 'Kopinor', url: 'https://kopinor.no/wp-content/uploads/2026/06/Arsmelding-2025.pdf' },
  mblReport: { title: 'Åpenhetsrapport, kollektiv forvaltning 2023 (transparency report, in Norwegian)', by: 'Mediebedriftenes Landsforening (MBL)', url: 'https://mediebedriftene.no/siteassets/dokumenter/apenhetslov/apenhetsrapport-kollektiv-forvaltning-2023.pdf' },
  // NDP Nieuwsmedia and GPT-NL
  ndpNews: { title: 'Dutch news publishers contribute to developing GPT-NL', by: 'IO+', url: 'https://ioplus.nl/en/posts/dutch-news-publishers-contribute-to-developing-gpt-nl' },
  gptRevenue: { title: 'Annex 6: Revenue Sharing Mechanism', by: 'TNO, GPT-NL', url: 'https://gpt-nl.nl/publish/pages/7064/annex_6_revenue_sharing_mechanism.pdf' },
  gptTemplate: { title: 'Content Contributor Agreement (template)', by: 'TNO, GPT-NL', url: 'https://gpt-nl.nl/publish/pages/7064/template_content_contributor_agreement_oktober_2025.pdf' },
  gptProtocol: { title: 'Annex 2: Training Content Protocol', by: 'TNO, GPT-NL', url: 'https://gpt-nl.nl/publish/pages/7064/annex_2_training_content_protocol.pdf' },
  gptCharter: { title: 'Annex 3: Governance Charter', by: 'TNO, GPT-NL', url: 'https://gpt-nl.nl/publish/pages/7064/annex_3_governance_charter.pdf' },
  gptRestrictions: { title: 'Annex 7: License Restrictions and Other Terms', by: 'TNO, GPT-NL', url: 'https://gpt-nl.nl/publish/pages/7064/annex_7_license_restrictions_other_terms.pdf' },
  tnoReport: { title: 'GPT-NL progress report (in Dutch)', by: 'TNO', url: 'https://publications.tno.nl/publication/34645720/dNo6mcVV/TNO-2026-R10516.pdf' },
  openFuture: { title: 'GPT-NL respects copyright: cui bono?', by: 'Open Future', url: 'https://openfuture.eu/blog/gpt-nl-respects-copyright-cui-bono/' },
  koTraining: { title: 'Trening av norske språkmodeller (in Norwegian)', by: 'Kopinor', url: 'https://kopinor.no/wp-content/uploads/2026/02/Trening-av-norske-sprakmodeller.pdf' },
  ilcPartners: { title: 'Partners', by: 'Internet Licensing Collective', url: 'https://internetcollective.org/partners' },
  // Around the world
  wStim: { title: 'STIM launches world\'s first collective AI music licence', by: 'CISAC, for STIM', url: 'https://www.cisac.org/Newsroom/society-news/stim-launches-worlds-first-collective-ai-music-licence' },
  wGema: { title: 'Generative AI licensing model', by: 'GEMA', url: 'https://www.gema.de/en/w/generative-ai-licensing-model' },
  wGemaPlai: { title: 'GEMA has just launched PLAI by GEMA, the first complete music dataset for simplified AI training, and signed up Klangio as the first customer', by: 'GEMA', url: 'https://www.gema.de/en/w/plai-by-gema-musikdatensatz' },
  wKopiostoFaq: { title: 'Frequently asked questions about the AI extension', by: 'Kopiosto', url: 'https://kopiosto.fi/en/kopiosto/for-users-of-works/copying-of-publications-and-works/companies-and-other-organisations/frequently-asked-questions/' },
  wKopiosto: { title: 'Let Kopiosto enforce your rights in AI development on your behalf', by: 'Kopiosto', url: 'https://kopiosto.fi/en/kopiosto/let-kopiosto-enforce-your-rights-in-ai-development-on-your-behalf/' },
  wSitra: { title: 'AI can create new business opportunities for media: a pilot project tests the marketplace concept', by: 'Sitra', url: 'https://www.sitra.fi/en/articles/ai-can-create-new-business-opportunities-for-media-a-pilot-project-tests-the-marketplace-concept/' },
  wCedro: { title: 'Un paso necesario para avanzar en el uso responsable de contenidos por la IA (in Spanish)', by: 'ElDerecho.com', url: 'https://elderecho.com/un-paso-necesario-para-avanzar-en-el-uso-responsable-de-contenidos-por-la-ia' },
  wDvp: { title: 'Droits voisins et IA : la presse attaque de nouveau Google devant l\'Autorité de la concurrence (in French)', by: 'Presse Agence', url: 'https://presseagence.fr/paris-droits-voisins-et-ia-la-presse-attaque-de-nouveau-google-devant-lautorite-de-la-concurrence/' },
  wApig: { title: 'Google AI Overviews : la presse française saisit l\'Autorité de la concurrence (in French)', by: 'Blog du Modérateur', url: 'https://www.blogdumoderateur.com/google-ai-overviews-presse-francaise-saisit-autorite-concurrence/' },
  wEpc: { title: 'European Publishers Council files formal antitrust complaint against Google over AI Overviews and AI Mode', by: 'European Publishers Council', url: 'https://www.epceurope.eu/post/european-publishers-council-files-formal-antitrust-complaint-against-google-over-ai-overviews-and-ai' },
  wCjeu: { title: 'La réutilisation d\'articles par un chatbot peut violer le droit de l\'UE (in French)', by: 'DH, via Belga', url: 'https://www.dhnet.be/dernieres-depeches/2026/11/03/la-reutilisation-darticles-par-un-chatbot-peut-violer-le-droit-de-lue-6HDNHHLYVFEM3PWKNHFKWQXAUE/' },
  wKpf: { title: '언론재단, AI 학습용 뉴스데이터 판매 개시... 97개 매체 제공 (in Korean)', by: 'Journalists Association of Korea', url: 'https://www.journalist.or.kr/news/article.html?no=56814' },
  wDaum: { title: '\'언론과 상생\' 내세운 포털 다음, \'AI 인용\'에 수익 지급키로 (in Korean)', by: 'Journalists Association of Korea', url: 'https://journalist.or.kr/news/article.html?no=61718' },
  wNskApril: { title: 'AI検索サービスに関する声明 (Statement on AI search services, in Japanese)', by: 'Japan Newspaper Publishers & Editors Association', url: 'https://www.pressnet.or.jp/statement/copyright/260420_16248.html' },
  wNskOct: { title: 'ＡＩの社会実装において、障害となる又は不十分な効果をもたらす規制・制度について (in Japanese)', by: 'Japan Newspaper Publishers & Editors Association', url: 'https://www.pressnet.or.jp/statement/copyright/261030_16372.html' },
  wJpSuits: { title: 'Asahi, Nikkei sue AI search outfit Perplexity for copyright infringement', by: 'The Register', url: 'https://www.theregister.com/2025/08/26/perplexity_asahi_nikkei_lawsuits/' },
  wAni: { title: 'Delhi High Court refuses interim injunction against OpenAI', by: 'SpicyIP', url: 'https://spicyip.com/2026/07/training-chatgpt-on-copyrighted-works-prima-facie-protected-under-indian-copyright-act-delhi-high-court-refuses-interim-injunction-against-openai.html' },
  wAniAppeal: { title: 'ANI takes AI training fight to appeal', by: 'LawChakra', url: 'https://lawchakra.in/high-court/delhi-high-court-ani-openai-appeal-notice-fair-dealing-chatgpt/' },
  wDpiit: { title: 'AI training and copyright in India: what the DPIIT hybrid model means for builders', by: 'Intepat', url: 'https://intepat.com/blog/ai-training-copyright-india-dpiit-hybrid-model' },
  wLinc: { title: 'Join the Internet Licensing Collective through LINC', by: 'LINC (IntentBridges Pte. Ltd.)', url: 'https://joinlinc.com/ilc/' },
  wAuAgency: { title: 'Collective licensing for AI', by: 'Copyright Agency', url: 'https://www.copyright.com.au/membership/ai-and-copyright-new-licensing-opportunities-for-members/collective-licensing-for-ai/' },
  wAuNbi: { title: 'Australia\'s News Bargaining Incentive passes Parliament', by: 'The Next Web', url: 'https://thenextweb.com/news/australia-news-bargaining-incentive-passes-parliament' },
  wCaOpenai: { title: 'Canadian news media companies v OpenAI: jurisdiction motion', by: 'Lenczner Slaght (counsel for the publishers)', url: 'https://www.litigate.com/canadian-news-media-companies-v-openai-jurisdiction-motion' },
  wCaAnthropic: { title: 'Canadian publishers launch copyright suit against AI company Anthropic', by: 'MobileSyrup', url: 'https://mobilesyrup.com/2026/10/19/canadian-publishers-launch-copyright-suit-against-ai-company-anthropic/' },
  wBrMeta: { title: 'Justiça proíbe Meta de usar conteúdo jornalístico sem autorização (in Portuguese)', by: 'Jornal do Comércio', url: 'https://www.jornaldocomercio.com/economia/2026/11/1269286-justica-proibe-meta-de-usar-conteudo-jornalistico-sem-autorizacao.html' },
  wBrBill: { title: 'IA e direitos autorais: o que diz o PL 2.338/23 aprovado pelo Senado (in Portuguese)', by: 'Migalhas', url: 'https://www.migalhas.com.br/depeso/422014/ia-e-direitos-autorais-o-que-diz-o-pl-2-338-23-aprovado-pelo-senado' },
  wZurich: { title: 'Verlegerverbände fordern Regeln für den Umgang von KI mit journalistischen Inhalten (in German)', by: 'Netzwoche', url: 'https://www.netzwoche.ch/news/2025-04-11/verlegerverbaende-fordern-regeln-fuer-den-umgang-von-ki-mit-journalistischen' },
  // FORA
  proto: { title: 'Protocol reference: FORA v1', by: 'FORA documentation', url: '/reference/proto-fora/' },
  terms: { title: 'Licensing terms', by: 'FORA documentation', url: '/protocol/licensing-terms/' },
  money: { title: 'How money flows', by: 'FORA documentation', url: '/getting-started/how-money-flows/' },
  discovery: { title: 'Discovery paths', by: 'FORA documentation', url: '/protocol/discovery-paths/' },
  broker: { title: 'FORA documentation, the Broker: discovery providers', by: 'FORA project' },
  essearch: { title: 'FORA Server source, Broker search provider', by: 'FORA project' },
  fora: { title: 'FORA project statement', by: 'FORA project' },
  implementer: { title: 'Implementer information', by: 'FORA project' },
  scorecard: { title: 'The scorecard in the article', by: 'FORA resources', url: '/resources/transparent-collective/#scorecard' },
} satisfies Record<string, Src>;

const at = (s: Src, locator?: string): EvidenceSource => ({ ...s, ...(locator ? { locator } : {}) });
/** A FORA spec claim: the readable reference page, the field in the locator. */
const ref = (anchor: string, field: string): EvidenceSource => ({ ...S.proto, url: `/reference/proto-fora/#${anchor}`, locator: field });

// Recurring quotes.
const Q = {
  ilcGuideUses: `The AI System uses the publisher’s licensed content under the ILC License, including for training, inference, and grounding, and tracks the usage required for reporting.`,
  ilcUsageFile: `The AI System sends the ILC Platform the licensing payment and a usage reporting file that includes its aggregated use of the publisher’s licensed content.`,
  ilcHeld: `Under the ILC License, these terms and restrictions apply wherever an authorized AI System obtains or uses the content, including content obtained directly from the publisher or through third parties, acquired before the RSL declaration was published, or otherwise held without a license governing its AI use.`,
  ilcNoVote: `Participation under this Agreement does not, by itself, make Publisher a member of ILC or confer any voting, governance, or other membership rights in ILC`,
  ilcNotDisclosed: `Detailed calculations and technical implementation procedures are established in the Allocation Rules and are not publicly disclosed.`,
  ilcFaqExclusive: `Is participation exclusive? No. Participation is non-exclusive. You keep the right to license your content directly to anyone, and any existing licensing deals remain unchanged.`,
  ilcExclude: `Publisher may elect not to participate in any Collective License Agreement with a particular AI Company, or may withdraw some or all of its Designated Content from that AI Company’s Repertoire, at any time and for any reason, by authenticated notice through the Platform.`,
  ilcYahoo: `Yahoo Scout, a new AI answers tool from Yahoo, is confirmed as ILC’s first commercial licensee.`,
  prPool: `“Revenue Share Percent” means the portion of Total Revenue (defined below) allocated for the pool of all content partners in the ProRata Offerings, which shall be fifty percent (50%) of the Total Revenue.`,
  prTotalRevenue: `“Total Revenue” means amounts earned and collected by ProRata from the ProRata Offerings including advertising, subscriptions, and sponsorships (if any)`,
  prFormula: `the product of Per Answer Revenue multiplied by the Revenue Share Percent and the Partner Per Answer Attribution Percent. - “Per Answer Revenue” means the Total Revenue divided by the number of Total Valid Answers in a given period.`,
  prNoTraining: `No. Publisher content supplied to ProRata for attribution is never used for model training.`,
  prRagOnly: `Publishers determine what content they provide, where it appears, and can opt-out at any time; ProRata’s RAG-only design ensures full removability.`,
  cometSplit: `we’re distributing all of that revenue to participating publishers, minus a small portion for Perplexity’s compute costs. Comet Plus is the first compensation model that allocates revenue to our partners based on three types of internet traffic: human visits, search citations, and agent actions.`,
  cccLicense: `CCC’s AI Systems Training License is a voluntary, non-exclusive collective license for organizations training AI systems for uses external to their organization. It provides the rights to lawfully use a wide and diverse repertoire of content for training AI systems, as well as the subsequent use of the trained system as a service`,
  plsUses: `Publishers decide: - whether to participate - which content they make available - the type of generative AI use they wish to license for (training and fine tuning, retrieval-augmented generation).`,
  plsRegulated: `PLS is regulated under the Collective Management of Copyright (EU Directive) Regulations 2016`,
  dpTest: `DPCMO indgik i november 2024 letter of intent med ProRata.AI og i december 2025 en rammeaftale med henblik på at kunne lancere en dansk version af Giat.AI baseret udelukkende på licenseret indhold. Projektet er en test og vil kræve tilslutning fra en kritisk masse af danske presseudgivere.`,
  dpTestNote: `Translation: "In November 2024 DPCMO entered a letter of intent with ProRata.AI, and in December 2025 a framework agreement, with a view to launching a Danish version of Giat.AI [sic, Gist.AI] based solely on licensed content. The project is a test and will require a critical mass of Danish press publishers to join."`,
  dpAssembly: `Den øverste myndighed i DPCMO er generalforsamlingen. Medlemmerne er repræsenteret på generalforsamlingen ved en repræsentation pr. medievirksomhed.`,
  dpAssemblyNote: `Translation: "The highest authority in DPCMO is the general assembly. The members are represented at the general assembly with one representation per media company."`,
  dpApproved: `Kulturministeriet har godkendt DPCMO som forvaltningsorganisation, der kan indgå aftaler med aftalicensvirkning`,
  dpApprovedNote: `Translation: "The Ministry of Culture has approved DPCMO as a management organisation that can enter into agreements with extended-collective-licence effect." DPCMO calls itself "en uafhængig, non-profit forening" (an independent non-profit association) in its transparency report.`,
  dpOpenai: `OpenAI has trained its models on works from Danish press publications at least until the summer of 2024`,
  koPrice: `An annual total remuneration of NOK 45,000,000 (in 2026) shall be paid for the use of protected material under this agreement.`,
  koPaid: `44,1 millioner kroner ble etter avtalen utbetalt til Mediebedriftenes Landsforening (MBL) før sommeren.`,
  koPaidNote: `Translation: "NOK 44.1 million was paid to Mediebedriftenes Landsforening (MBL) under the agreement before the summer." MBL is the Norwegian media businesses' association.`,
  koScope: `This agreement applies to the reproduction and use of text for the National Library’s training of language models from copyright-protected press publications published in Norway up to one year from the date of publication.`,
  koRegulated: `Kopinor er omfattet av lov om kollektiv forvaltning av opphavsrett mv. og står under tilsyn av Patentstyret.`,
  koRegulatedNote: `Translation: "Kopinor is covered by the act on collective management of copyright and is supervised by the Norwegian Industrial Property Office."`,
  koSelection: `The National Library shall determine which publications are used in the training of the various language models.`,
  koPretraining: `This agreement is limited to regulating the National Library’s training of language models on the data governed by this agreement. It does not affect any pre-training that the base models used by the National Library may have undergone.`,
  offerSig: `REQUIRED. Hex-encoded detached Ed25519 signature over the canonical serialization of the ENTIRE Offer — every field, including \`pricing\`, \`terms\` (the full licensing payload), \`expires_at\`, and \`exchange\`.`,
  acceptance: `The agent's detached acceptance signature over this item's \`offer\`.`,
  money: `FORA never touches money. It follows the OpenRTB model: the protocol handles authorization and logging, while actual settlement happens outside the protocol through existing billing infrastructure.`,
  manyTerms: `A resource carries zero or more \`LicenseTerm\` entries, at most 32. Each term is a complete, self-contained access arrangement, and a resource with several terms is the normal case.`,
  brokerSearch: `A Broker runs one catalog search, which its operator chooses per deployment. The search only proposes URIs: prices, license terms and signatures always come from the Exchange, so a search result cannot produce an offer the Exchange does not stand behind.`,
  ndpLicensed: `Members of NDP Nieuwsmedia are providing access to their archives, which include articles from over 30 national and regional news titles.`,
  gptRetain: `TNO will retain 50% of Net Revenues generated with the GPT-NL Model.`,
  gptOptions: `Content Contributors can opt for one of three options: 1) no compensation is claimed, 2) a proportionate share of 50% of the Net Revenues (as defined below) generated with the GPT-NL Model`,
  gptRule: `The quantity of an individual dataset is determined by the number of Tokens that ends up in the Prepared Dataset. … The quality of a dataset depends on the oversampling multiplier used.`,
  gptShare: `The share that a Content Contributor can expect is proportionate to the Data Value of the individual dataset as a relative percentage of the Data Value of the Prepared Dataset.`,
  gptSelect: `Content Contributors each select the training content that they want to contribute to the GPT-NL project.`,
  gptTraining: `license content to TNO for the training and future updating of the GPT-NL Model.`,
  wZurich: `Internationale Online-Plattformen müssen die journalistische Pluralität achten und sich dieser gegenüber neutral verhalten, sie dürfen weder eigene Inhalte noch Inhalte einzelner Medien privilegieren`,
  wZurichNote: `Translation: "International online platforms must respect journalistic plurality and stay neutral towards it; they may favor neither their own content nor that of individual outlets."`,
};

// One scorecard cell.
const cell = (row: string, topic: string, scheme: string, claim: string, quote: string | undefined, source: EvidenceSource, kind: EvidenceKind, note?: string): EvidenceClaim => ({
  id: `sc-${row}-${scheme}`, topic, claim, ...(quote ? { quote } : {}), source, kind, ...(note ? { note } : {}),
});
const R1 = 'Who pays you today?';
const R2 = 'Which uses do you license, and who picks them?';
const R3 = 'Who picks whose content gets used, and is the method published?';
const R4 = 'Who counts the use your share rests on?';
const R5 = 'Is the split rule published?';
const R6 = 'What does the operator keep?';
const R7 = 'Is it regulated, and do members vote?';
const R8 = 'Does it reach copies an AI company took before any license?';
const NOT_STATED = 'Not stated: the scheme\'s public pages don\'t say.';

// The basis of every "A pool today" cell: the scorecard rows below.
const TODAY_BASIS = 'A summary of the eight schemes, so its basis is the scorecard rows on this page, not one source.';

export const EVIDENCE: EvidenceGroup[] = [
  {
    id: 'journey',
    title: 'Same money. Open boxes.',
    claims: [
      {
        id: 'journey-operator', topic: 'The collective',
        claim: 'A trade group, a publisher alliance or a company working for one runs the collective as its operator.',
        quote: `(operated by an Exchange operator, provider, or third party) handles all billing through its pluggable Billing Adapter`,
        source: at(S.money, '"The Billing Chain"'), kind: 'primary',
        note: 'The quote describes the Exchange. FORA lets any organisation operate one; that a collective runs this way is the article\'s design.',
      },
      {
        id: 'journey-in-today', topic: 'What you put in',
        claim: 'A pool today: the uses the scheme defines, every AI use or a fixed list.',
        quote: Q.ilcGuideUses, source: at(S.ilcGuide, '"How ILC licensing works"'), kind: 'reading',
        note: `${TODAY_BASIS} Row "Which uses do you license, and who picks them?" (#sc-uses-ilc to #sc-uses-ndp): ILC grants every AI use; ProRata, Kopinor and NDP fix the list; CLA lets the publisher pick between the two uses it lists.`,
      },
      { id: 'journey-in-fora', topic: 'What you put in', claim: 'On FORA: your own terms, as simple or as detailed as you want.', quote: Q.manyTerms, source: at(S.terms, '"Overview"'), kind: 'primary' },
      {
        id: 'journey-picked-today', topic: 'Picked',
        claim: 'A pool today: the AI company\'s or the operator\'s own system picks, and no scheme publishes how it picks for an answer.',
        quote: Q.koSelection, source: at(S.koAgreement, '§6'), kind: 'reading',
        note: `${TODAY_BASIS} Row "Who picks whose content gets used" (#sc-picks-ilc to #sc-picks-ndp). The quote is the one contract that names the picker. GPT-NL publishes how TNO weights its training set, not how the model picks for an answer.`,
      },
      { id: 'journey-picked-fora', topic: 'Picked', claim: 'On FORA: the operator\'s search picks.', quote: Q.brokerSearch, source: at(S.broker), kind: 'primary' },
      { id: 'journey-picked-publish', topic: 'Picked', claim: 'The operator can publish the method.', quote: `The query is configuration, not code.`, source: at(S.essearch, 'src/broker/internal/essearch/doc.go'), kind: 'reading', note: 'The ranking is the operator\'s own search template, a configuration it can publish. FORA doesn\'t require publication. FORA Server isn\'t a public repository, so there is no URL.' },
      {
        id: 'journey-counted-today', topic: 'Counted',
        claim: 'A pool today: the payer\'s own report or engine counts, or no one counts at all.',
        quote: Q.ilcUsageFile, source: at(S.ilcGuide, '"How ILC licensing works"'), kind: 'reading',
        note: `${TODAY_BASIS} Row "Who counts the use your share rests on?" (#sc-counts-ilc to #sc-counts-ndp). CCC and CLA haven't said how they will count AI use.`,
      },
      { id: 'journey-counted-fora', topic: 'Counted', claim: 'On FORA: a signed record of every fetch, which the payer didn\'t write.', quote: Q.offerSig, source: ref('offer', 'Offer.signature'), kind: 'primary', note: 'The Exchange signs the offer; the AI company signs its acceptance (TransactionItem.agent_acceptance).' },
      {
        id: 'journey-split-today', topic: 'Split',
        claim: 'A pool today: undisclosed rules or weights, in seven of the eight schemes; GPT-NL publishes its split rule.',
        quote: Q.ilcNotDisclosed, source: at(S.policy, '§1'), kind: 'reading',
        note: `${TODAY_BASIS} Row "Is the split rule published?" (#sc-split-ilc to #sc-split-ndp). GPT-NL: #sc-split-ndp.`,
      },
      { id: 'journey-split-fora', topic: 'Split', claim: 'On FORA: a published formula and published weights.', source: at(S.fora), kind: 'reading', note: 'The article\'s design: the formula and the weights are the pool\'s published terms. The protocol leaves the money outside it, so the operator publishes them.' },
      {
        id: 'journey-see-today', topic: 'You see',
        claim: 'A pool today: a statement, at most.',
        quote: `Publisher shall treat such summaries, royalty statements, and other nonpublic information made available through the Platform as confidential information of ILC.`,
        source: at(S.ppa, '§7.5'), kind: 'reading',
        note: `${TODAY_BASIS} ILC and ProRata send statements (#adds-statements); for Perplexity, CCC and Kopinor no statement was found.`,
      },
      { id: 'journey-see-fora', topic: 'You see', claim: 'On FORA: your own records, and you can redo the sum.', quote: Q.offerSig, source: ref('offer', 'Offer.signature'), kind: 'reading', note: 'The protocol creates a signed record per fetch; showing a publisher its records and a statement with the totals is the operator\'s job in the article\'s design.' },
      {
        id: 'journey-selection', topic: 'The main point',
        claim: 'None of the eight schemes publishes how an AI system picks whose content to use in an answer, and in a pool split by use that pick decides who gets paid.',
        source: at(S.scorecard), kind: 'reading',
        note: 'Based on absence, across the scorecard row "Who picks whose content gets used" (#sc-picks-ilc to #sc-picks-ndp). GPT-NL publishes a training-set weighting, not an answer-time rule.',
      },
      {
        id: 'journey-hero', topic: 'The collective',
        claim: 'A collective is fair when each member can see what the pool collects and check its own share.',
        source: at(S.fora), kind: 'reading',
        note: 'The article\'s premise. The parts that make it checkable on FORA are in the cards below; the schemes\' answers are in the scorecard.',
      },
      {
        id: 'journey-formula', topic: 'The formula',
        claim: 'Each AI company pays the greater of a share of its own revenue and a floor per fetch, up to a cap, so the pool never falls below the floor; the formula and the per-fetch floor are published, and each AI company\'s rate and cap are in its agreement with the operator.',
        quote: `A revenue share has no price at transaction time: its rate and its settlement are an agreement between the agent and the publisher outside this protocol.`,
        source: at(S.terms, '"Revenue-share arrangements"'), kind: 'reading',
        note: 'A design, not a source fact: min(cap, max(rate × its revenue, floor × fetches)); your pay = (pool − operator\'s cut) × your weight ÷ all members\' weight. The protocol leaves rates and settlement to the parties\' agreement.',
      },
    ],
  },
  {
    id: 'today',
    title: 'How collectives run today',
    claims: [
      // ILC
      { id: 'ilc-launch', topic: 'Internet Licensing Collective (ILC)', claim: 'ILC launched on November 12, 2026, with Yahoo Scout as its first licensee.', quote: Q.ilcYahoo, source: at(S.ilcPress), kind: 'primary' },
      { id: 'ilc-negotiated-fee', topic: 'Internet Licensing Collective (ILC)', claim: 'An AI company takes one blanket license for a negotiated fee, which ILC doesn\'t publish.', quote: `License fees are negotiated to reflect the economic value of the rights and content made available to AI licensees.`, source: at(S.policy, '§2.1'), kind: 'primary', note: 'The participation agreement: "ILC shall not be required to disclose exact negotiated rates, confidential pricing, or other commercially sensitive terms" (§2.2).' },
      { id: 'ilc-reports-own-use', topic: 'Internet Licensing Collective (ILC)', claim: 'The AI company reports its own use.', quote: Q.ilcUsageFile, source: at(S.ilcGuide, '"How ILC licensing works"'), kind: 'primary' },
      { id: 'ilc-non-exclusive', topic: 'Internet Licensing Collective (ILC)', claim: 'Participation in ILC is non-exclusive.', quote: Q.ilcFaqExclusive, source: at(S.ilcFaq, '"Is participation exclusive?"'), kind: 'primary', note: 'The participation agreement: designation "is non-exclusive and does not restrict direct licensing" (§3.5).' },
      { id: 'ilc-exclude', topic: 'Internet Licensing Collective (ILC)', claim: 'A publisher can exclude a specific AI company.', quote: Q.ilcExclude, source: at(S.ppa, '§2.4'), kind: 'primary' },
      { id: 'ilc-choose-uses', topic: 'Internet Licensing Collective (ILC)', claim: 'ILC\'s site tells publishers: "Choose which AI uses you authorize".', quote: `For what purposes Choose which AI uses you authorize.`, source: at(S.ilcPublishers, '"You decide"'), kind: 'primary' },
      { id: 'ilc-uses-agreement', topic: 'Internet Licensing Collective (ILC)', claim: 'Uses are all or nothing: the participation agreement sets the uses in each AI company\'s license.', quote: `Publisher agrees to participate in Collective License Agreements negotiated by ILC for the uses of Publisher’s Content expressly authorized under each applicable Collective License Agreement (the “Permitted Uses”).`, source: at(S.ppa, '§2.1'), kind: 'primary', note: '"All or nothing" is the article\'s summary: the publisher\'s lever in the agreement is to exclude an AI company (§2.4); no clause lets it keep an AI company and narrow the uses.' },
      { id: 'ilc-uses-portal', topic: 'Internet Licensing Collective (ILC)', claim: 'The check in ILC\'s publisher portal accepts only a license declaration, the file where a publisher states its terms, that grants every AI use, training included.', quote: `The RSL declaration does not permit the required AI uses. Include a permits element with type="usage" and ai-all.`, source: at(S.portal), kind: 'primary', note: 'Shown to publishers in ILC\'s portal. ai-all is RSL\'s term for every AI use; ILC\'s public guide says the AI system uses the content "including for training, inference, and grounding".' },
      { id: 'ilc-no-black-box', topic: 'Internet Licensing Collective (ILC)', claim: 'The launch release says "There is no black box".', quote: `There is no black box: ILC distributes licensing revenue according to its Allocation Rules`, source: at(S.ilcPress), kind: 'primary' },
      { id: 'ilc-not-disclosed', topic: 'Internet Licensing Collective (ILC)', claim: 'The Royalty Distribution Policy says the detailed calculations are not publicly disclosed.', quote: Q.ilcNotDisclosed, source: at(S.policy, '§1'), kind: 'primary', note: 'Repeated in §13.3.' },
      // ProRata
      { id: 'prorata-fifty', topic: 'ProRata / Gist', claim: 'ProRata\'s partner agreement puts 50% of the total revenue of its own answer products into one pool for all content partners.', quote: Q.prPool, source: at(S.prMsa, 'definitions'), kind: 'primary' },
      { id: 'prorata-attribution', topic: 'ProRata / Gist', claim: 'ProRata\'s attribution engine splits the pool.', quote: `“Partner Per Answer Revenue Share” means the amount of revenue allocated to Partner for a given Answer from the Answer Engine based upon the proportional contribution from Partner’s Content to such Answer`, source: at(S.prMsa, 'definitions'), kind: 'primary', note: 'The partner\'s share is "the product of Per Answer Revenue multiplied by the Revenue Share Percent and the Partner Per Answer Attribution Percent".' },
      { id: 'prorata-no-outside-payer', topic: 'ProRata / Gist', claim: 'No outside AI company pays in.', quote: Q.prTotalRevenue, source: at(S.prMsa, 'definitions'), kind: 'reading', note: 'The pool is a share of ProRata\'s own revenue from its own offerings; no third-party AI licensee is named on ProRata\'s or Gist\'s pages.' },
      { id: 'prorata-no-training', topic: 'ProRata / Gist', claim: 'Partner content is never used for model training.', quote: Q.prNoTraining, source: at(S.prPublishers, 'FAQ'), kind: 'primary' },
      // Perplexity
      { id: 'pplx-announced', topic: 'Perplexity Comet Plus', claim: 'Perplexity announced Comet Plus in August 2025.', quote: `Comet Plus is a new subscription that gives Perplexity users access to premium content from a group of trusted publishers and journalists. Aug 25, 2025`, source: at(S.comet), kind: 'primary' },
      { id: 'pplx-split', topic: 'Perplexity Comet Plus', claim: 'Subscription revenue goes to participating publishers, minus a small portion for Perplexity\'s compute costs, split by human visits, search citations and agent actions.', quote: Q.cometSplit, source: at(S.comet), kind: 'primary' },
      { id: 'pplx-only-payer', topic: 'Perplexity Comet Plus', claim: 'Perplexity runs the pool and is its only payer.', quote: `Comet Plus will be a $5 standalone subscription. Pro and Max subscribers get Comet Plus included in their memberships.`, source: at(S.comet), kind: 'reading', note: 'The pool is Perplexity\'s own subscription revenue, allocated by Perplexity; no other payer is described.' },
      { id: 'pplx-partners', topic: 'Perplexity Comet Plus', claim: 'Its launch partners were Condé Nast, Fortune, Le Figaro, Le Monde, the Los Angeles Times and The Washington Post.', quote: `We are honored to launch Comet Plus with some of the world’s best-known, most respected sources of news and culture: Conde Nast, publishers of The New Yorker, Wired, Architectural Digest, Allure, Ars Technica, Bon Appétit, Condé Nast Traveler, Epicurious, GQ, Glamour, Pitchfork, Self, Teen Vogue, them, Vanity Fair, and Vogue. Fortune Le Figaro Le Monde The Los Angeles Times The Washington Post`, source: at(S.cometPartners), kind: 'primary', note: 'The names after Condé Nast\'s list are a list of logos on the page.' },
      { id: 'pplx-launched', topic: 'Perplexity Comet Plus', claim: 'Comet Plus launched in 2025.', quote: `Oct 1, 2025 … We are honored to launch Comet Plus with some of the world’s best-known, most respected sources of news and culture`, source: at(S.cometPartners), kind: 'primary' },
      { id: 'pplx-pricing-absent', topic: 'Perplexity Comet Plus', claim: 'Perplexity\'s pricing page doesn\'t list Comet Plus.', source: at(S.pplxPricing), kind: 'reading', note: 'Absence: the pricing page mentions Comet and Comet Assistant, and Comet Plus nowhere.' },
      { id: 'pplx-cnn-agreement', topic: 'Perplexity Comet Plus', claim: 'CNN\'s short agreement with Perplexity never became final.', quote: `“CNN’s short form agreement did not lead to a final agreement between the parties due to the inability to agree on multiple issues, including limits on Perplexity’s use of CNN content in its answers to users,” the lawsuit reads.`, source: at(S.cnnSuit), kind: 'reported' },
      { id: 'pplx-cnn', topic: 'Perplexity Comet Plus', claim: 'CNN sued Perplexity in May 2026.', quote: `JD Knapp May 28, 2026 … The lawsuit filed Thursday in United States District Court – Southern District of New York`, source: at(S.cnnSuit), kind: 'reported' },
      // CCC
      { id: 'ccc-license', topic: 'CCC AI Systems Training License', claim: 'CCC describes a voluntary, non-exclusive collective license for training AI systems and for the trained system\'s later use as a service.', quote: Q.cccLicense, source: at(S.cccSheet), kind: 'primary' },
      { id: 'ccc-open', topic: 'CCC AI Systems Training License', claim: 'CCC tells rightsholders: "This license is open for your participation."', quote: `This license is open for your participation.`, source: at(S.cccSheet), kind: 'primary' },
      { id: 'ccc-nothing-named', topic: 'CCC AI Systems Training License', claim: 'CCC\'s public pages name no licensee, no price and no distribution rule for it.', quote: `Rightsholders receive royalty distributions electronically from CCC.`, source: at(S.cccSheet), kind: 'reading', note: 'Absence: this is all the overview sheet says about distribution, and no licensee or price appears on CCC\'s pages. A licensing tracker records "No public adoption figure found" (datalicenses.org).' },
      // CLA
      { id: 'cla-building', topic: 'CLA, with PLS and ALCS', claim: 'The Copyright Licensing Agency is building a generative AI license with PLS, for publishers, and ALCS, for authors.', quote: `the initiative invites publishers to opt-in to a collective licence scheme, which has been developed along with the Copyright Licensing Agency (CLA) and the Authors' Licensing and Collecting Society (ALCS).`, source: at(S.plsNews), kind: 'primary' },
      { id: 'cla-regulated', topic: 'CLA, with PLS and ALCS', claim: 'CLA and PLS are regulated collectives.', quote: Q.plsRegulated, source: at(S.plsReport, '"Compliance and code of conduct"'), kind: 'primary', note: 'CLA: "CLA is a collective management organisation (CMO) and is controlled by its members" (CLA annual transparency report 2025, §6).' },
      { id: 'cla-uses', topic: 'CLA, with PLS and ALCS', claim: 'Publishers decide the type of generative AI use they license, and PLS names two: training and retrieval.', quote: Q.plsUses, source: at(S.plsNews, '"Is the scheme mandatory?"'), kind: 'primary' },
      { id: 'cla-nla', topic: 'CLA, with PLS and ALCS', claim: 'Publishers that license through NLA Media Access can\'t join.', quote: `this licensing is available only to those publishers that license through CLA rather than NLA Media Access for Business and Public Sector licensing.`, source: at(S.plsNews, '"Which publishers does this apply to?"'), kind: 'primary' },
      { id: 'cla-no-licensee', topic: 'CLA, with PLS and ALCS', claim: 'No AI licensee has been announced, and the license terms sit behind PLS\'s member login.', quote: `Publishers are now being invited to opt in to the scheme. Following this stage, PLS will work with the Copyright Licensing Agency and AI developers to implement the licensing framework and enable AI companies to license content through the system.`, source: at(S.plsNews, '"What happens next?"'), kind: 'reading', note: 'Absence: no licensee is named on CLA\'s or PLS\'s pages. The opt-in page in PLS\'s publisher area shows a sign-in screen only.' },
      // DPCMO
      { id: 'dpcmo-regulated', topic: 'DPCMO', claim: 'Denmark\'s collective for press publishers is regulated.', quote: `Danske Pressepublikationers Kollektive Forvaltningsorganisation/Danish Press Publications Collective Management Organisation; forkortet DPCMO.`, source: at(S.dpHome), kind: 'primary', note: 'DPCMO is a collective management organisation under Danish law. Its approval to make extended-collective-licence agreements "gælder fra d.d. til og med den 26. september 2026" (applies until 26 September 2026), says the Ministry of Culture\'s decision; no renewal was found.' },
      { id: 'dpcmo-vote', topic: 'DPCMO', claim: 'Its members vote in a general assembly.', quote: Q.dpAssembly, source: at(S.dpReport, 'page 4'), kind: 'primary', note: Q.dpAssemblyNote },
      { id: 'dpcmo-prorata-test', topic: 'DPCMO', claim: 'Its one signed AI agreement is a framework with ProRata, which its transparency report calls a test; each member opts in on its own.', quote: Q.dpTest, source: at(S.dpReport), kind: 'primary', note: `${Q.dpTestNote} DPCMO's announcement: "Participation is free and non-exclusive". Its agreements with Mistral, Cloudflare and TollBit are letters of intent.` },
      { id: 'dpcmo-openai', topic: 'DPCMO', claim: 'In February 2026, DPCMO took OpenAI to court.', quote: Q.dpOpenai, source: at(S.dpOpenai), kind: 'primary', note: 'DPCMO\'s announcement is titled "A united Danish media industry takes OpenAI to court".' },
      // Kopinor
      { id: 'kopinor-scope', topic: 'Kopinor and the National Library of Norway', claim: 'Kopinor licensed the National Library to train Norwegian language models on newspapers.', quote: Q.koScope, source: at(S.koAgreement, '§2'), kind: 'primary', note: 'Kopinor\'s announcement: "Avtalen regulerer bruk av innhold fra norske aviser i trening av norske språkmodeller." (The agreement governs the use of content from Norwegian newspapers in training Norwegian language models.)' },
      { id: 'kopinor-price', topic: 'Kopinor and the National Library of Norway', claim: 'The contract sets an annual total of NOK 45 million for 2026.', quote: Q.koPrice, source: at(S.koAgreement, '§17'), kind: 'primary' },
      { id: 'kopinor-only-price', topic: 'Kopinor and the National Library of Norway', claim: 'It is the one published price among these schemes.', quote: Q.koPrice, source: at(S.koAgreement, '§17'), kind: 'reading', note: 'Across the scorecard\'s "Who pays you today?" and "What does the operator keep?" rows, no other scheme publishes an amount. GPT-NL publishes its split rule and TNO\'s 50% share, but "TNO will determine the license fee for the Professional License (and any other paid license types) at its discretion" (template agreement §7.2).' },
      { id: 'kopinor-paid', topic: 'Kopinor and the National Library of Norway', claim: 'Kopinor paid NOK 44.1 million to MBL, the Norwegian media businesses\' association.', quote: Q.koPaid, source: at(S.koPayout), kind: 'primary', note: Q.koPaidNote },
      { id: 'kopinor-closed', topic: 'Kopinor and the National Library of Norway', claim: 'It has one licensee and covers Norwegian press only.', quote: Q.koScope, source: at(S.koAgreement, '§2'), kind: 'primary', note: 'The agreement is between Kopinor and the National Library alone, and covers press publications published in Norway.' },
      // NDP
      { id: 'ndp-licensed', topic: 'NDP Nieuwsmedia and GPT-NL', claim: 'NDP Nieuwsmedia licensed articles from more than 30 news titles, plus the news agency ANP, to TNO to train GPT-NL.', quote: `${Q.ndpLicensed} … News agency ANP is also participating`, source: at(S.ndpNews), kind: 'reported', note: 'IO+: "Dutch news publishers are collaborating with the Netherlands Institute of Applied Scientific Research (TNO) to develop further GPT-NL".' },
      { id: 'ndp-fifty', topic: 'NDP Nieuwsmedia and GPT-NL', claim: 'Contributors who choose revenue sharing split 50% of the net revenue from licensing the model; the template also offers no compensation, or a one-time payment. TNO keeps 50%.', quote: `${Q.gptOptions} and a proportionate discount on their professional license fee, or 3) a one-time upfront compensation and a proportionate discount on their professional license fee. … ${Q.gptRetain}`, source: at(S.gptRevenue), kind: 'primary' },
      { id: 'ndp-reinvested', topic: 'NDP Nieuwsmedia and GPT-NL', claim: 'TNO\'s half will be re-invested in the model.', quote: `TNO’s share of the Net Revenues will be re-invested to cover cost of the further development and maintenance of the GPT-NL Model and the Research Facility`, source: at(S.gptTemplate), kind: 'primary' },
      { id: 'ndp-rule', topic: 'NDP Nieuwsmedia and GPT-NL', claim: 'Each share is a token count times a quality multiplier.', quote: Q.gptRule, source: at(S.gptRevenue, '§2.1.2–2.1.3'), kind: 'primary', note: `The share: "${Q.gptShare}" (§2.1). Some of the PDF's formulas are images and didn't extract.` },
      { id: 'ndp-choose-filter', topic: 'NDP Nieuwsmedia and GPT-NL', claim: 'Publishers choose what to contribute, and TNO filters and weights it.', quote: Q.gptSelect, source: at(S.gptProtocol), kind: 'primary', note: 'TNO\'s weighting: "In the case of GPT-NL, high-quality Tokens can be repeated up to roughly 10 times for optimal performance", and where two sets overlap, "the data for which a Content Contributor Agreement was signed latest, will get deleted" (Annex 6 §2.1.2–2.1.3).' },
      { id: 'ndp-exit', topic: 'NDP Nieuwsmedia and GPT-NL', claim: 'Leaving takes six months\' notice, and models already trained may be used for two more years.', quote: `Either Party shall have the right to terminate this Agreement for convenience upon six (6) months prior written notice to the other Party with effect to the end of each contract year. … for a period of 2 years after the effective date of termination`, source: at(S.gptTemplate, '§13.2, §13.4'), kind: 'primary' },
      { id: 'ndp-template', topic: 'NDP Nieuwsmedia and GPT-NL', claim: 'The published terms are TNO\'s template; NDP\'s own contract isn\'t public.', quote: `iedere licentieovereenkomst met dataproviders gelden uniforme … regels en deze afspraken zijn openbaar te vinden op onze`, source: at(S.tnoReport), kind: 'reading', note: 'Translation: "the same rules apply to every license agreement with data providers, and these arrangements can be found publicly on our [website]". The report\'s two-column layout splits the sentence. That NDP\'s contract follows the template is an inference from it; NDP\'s contract itself wasn\'t found.' },
      { id: 'ndp-no-payout', topic: 'NDP Nieuwsmedia and GPT-NL', claim: 'No paying licensee of the model and no payout has been shown.', quote: `the participating news media receive no payment upfront and instead share in the proceeds if the model generates revenue.`, source: at(S.openFuture), kind: 'reading', note: 'Absence: no paying licensee of GPT-NL or payout to contributors was found in TNO\'s or NDP\'s public documents.' },
      { id: 'ndp-closed', topic: 'NDP Nieuwsmedia and GPT-NL', claim: 'The license covers NDP\'s Dutch member titles only.', quote: Q.ndpLicensed, source: at(S.ndpNews), kind: 'reading', note: 'NDP licensed its members\' archives; a publisher outside NDP isn\'t covered by it.' },
      { id: 'today-music', topic: 'Music', claim: 'Music has run on pools for decades; a streaming service is a licensing collective with a player on top.', quote: `Every month, in every country, we calculate streamshare like this: your streams in that market ÷ total streams in that market = your share of that market’s royalty pool.`, source: { title: 'Loud & Clear: FAQ', by: 'Spotify', url: 'https://loudandclear.byspotify.com/faq/' }, kind: 'reading', note: 'The music comparison and its sources are on /resources/music-dsp/. Spotify\'s rule is one example of a pool split by a published formula.' },
    ],
  },
  {
    id: 'world',
    title: 'Around the world',
    claims: [
      { id: 'w-stim', topic: 'Europe', claim: 'Sweden: STIM runs a collective license for AI training and output; its first licensee is Songfox.', quote: `A new framework allows AI companies to train their systems on copyrighted music lawfully, with royalties flowing back to the original songwriters. Compensation flows both through model training and the downstream consumption of AI outputs. … The first company to operate under the new licence will be Songfox`, source: at(S.wStim), kind: 'primary' },
      { id: 'w-gema-plai', topic: 'Europe', claim: 'Germany: GEMA licensed a training dataset to Klangio.', quote: `GEMA has just launched PLAI by GEMA, the first complete music dataset for simplified AI training, and signed up Klangio as the first customer`, source: at(S.wGemaPlai), kind: 'primary' },
      { id: 'w-gema', topic: 'Europe', claim: 'Germany: GEMA also publishes a licensing model at 30% of an AI provider\'s net income, with no licensee found.', quote: `The licensing approach provides a 30% share of all net income generated by the generative AI model or system of the provider.`, source: at(S.wGema), kind: 'primary', note: 'No licensee of this model was found.' },
      { id: 'w-kopiosto', topic: 'Europe', claim: 'Finland: Kopiosto\'s AI license covers a company\'s own staff, not AI developers.', quote: `Kopiosto’s copying licence will be extended to cover the use and prompting of artificial intelligence (AI) applications used internally by organisations.`, source: at(S.wKopiostoFaq), kind: 'reading', note: 'The FAQ defines an internal AI application as one "with access restricted only to the organisation’s staff". No Kopiosto license for AI developers was found.' },
      { id: 'w-sitra', topic: 'Europe', claim: 'Finland: in a pilot, Finnish news media are testing content use and pricing models with AI developers.', quote: `This work led to a pilot in which Finnish news media organisations are testing content use and pricing models with AI developers.`, source: at(S.wSitra), kind: 'primary' },
      { id: 'w-cedro', topic: 'Europe', claim: 'Spain: CEDRO signed as the exclusive Spanish partner of the RSL Collective, and has no license yet.', quote: `Nuestra Entidad se incorpora como socio exclusivo de la organización estadounidense en España`, source: at(S.wCedro), kind: 'reported', note: 'Translation: "Our organisation joins as the exclusive partner of the US organisation in Spain" (the organisation being the RSL Collective, named earlier in the article). No CEDRO AI license was found.' },
      { id: 'w-cedro-name', topic: 'Europe', claim: 'The RSL Collective is a name ILC\'s partner page still uses.', quote: `LINC brings local publisher relationships and market expertise to RSL Collective`, source: at(S.ilcPartners), kind: 'primary' },
      { id: 'w-dvp', topic: 'Europe', claim: 'France: DVP went to the competition authority in 2026 over Google\'s AI Overviews and AI Mode.', quote: `avoir saisi l’Autorité de la concurrence pour des manquements de Google à ses engagements. En cause, le déploiement en France des fonctionnalités d’intelligence artificielle « AI Overviews » et « AI Mode »`, source: at(S.wDvp), kind: 'reported', note: 'Translation: "[DVP announced it had] referred Google\'s breaches of its commitments to the competition authority. At issue: the rollout in France of the AI features AI Overviews and AI Mode."' },
      { id: 'w-apig', topic: 'Europe', claim: 'France: APIG went to the competition authority in 2026 over AI Overviews and AI Mode.', quote: `L’organisme, qui représente près de 300 quotidiens français, demande à l’Autorité de la concurrence d’intervenir face au déploiement unilatéral des AI Overviews et de l’AI Mode.`, source: at(S.wApig), kind: 'reported', note: 'Translation: "The body, which represents nearly 300 French dailies, asks the competition authority to act on the unilateral rollout of AI Overviews and AI Mode."' },
      { id: 'w-epc', topic: 'Europe', claim: 'European Union: the European Publishers Council filed an antitrust complaint over Google\'s AI Overviews.', quote: `The European Publishers Council (EPC) has filed a formal complaint with the European Commission alleging that Google LLC and Alphabet Inc. are abusing their dominant position in general search services, in breach of Article 102 TFEU, through the deployment of AI Overviews and AI Mode within Google Search.`, source: at(S.wEpc), kind: 'primary' },
      { id: 'w-cjeu', topic: 'Europe', claim: 'An Advocate General at the EU\'s top court says chatbot answers can infringe press publishers\' rights.', quote: `réutilisation en temps réel d'articles de presse par un chatbot d'intelligence artificielle peut porter atteinte aux droits des éditeurs lorsqu'elle franchit certaines lignes rouges, a conclu mardi l'avocat général à la Cour de Justice de l'Union européenne.`, source: at(S.wCjeu), kind: 'reported', note: 'Translation: "real-time reuse of press articles by an AI chatbot can infringe publishers\' rights when it crosses certain red lines, the Advocate General at the Court of Justice of the European Union concluded on Tuesday."' },
      { id: 'w-kpf', topic: 'Asia', claim: 'Korea: the Korea Press Foundation sells news data for AI training from the outlets it manages in trust, 97 of them in 2024; each outlet sets its own price, and no buyer is named.', quote: `언론재단은 127개사의 뉴스저작물을 신탁 받아 관리 중인데 현재 신문, 인터넷신문, 방송사 97개 매체의 뉴스데이터를 이용할 수 있다고 밝혔다. … 구체적인 판매 요금은 각 언론사가 정한다.`, source: at(S.wKpf), kind: 'reported', note: 'Translation: "The Press Foundation manages news works from 127 companies in trust, and said news data from 97 newspapers, internet newspapers and broadcasters is currently available. … Each news outlet sets the specific sale price." No buyer is named. The source is a 2024 report; no later one was found.' },
      { id: 'w-daum', topic: 'Asia', claim: 'Korea: the portal Daum plans a pool of KRW 2 billion a year for partner outlets, split each quarter by how often its own AI summaries cite them.', quote: `구체적으론 향후 다음 검색에 더 적극 도입될 ‘AI 요약’에서 ‘AI의 인용 사용량’을 측정해 지급하는 방식이 제시됐다. 연 20억원 예산을 책정하고 ‘서비스 참여 의사’나 ‘데이터 활용 동의’를 한 매체에 대해 분기 단위로 기여도에 따라 금액을 분배한다는 구상이다.`, source: at(S.wDaum), kind: 'reported', note: 'Translation: "Specifically, it proposed measuring and paying by \'AI citation usage\' in the \'AI summaries\' to be introduced more widely in Daum search. The plan is to set a budget of KRW 2 billion a year and distribute it each quarter, by contribution, to outlets that agree to take part or to let their data be used."' },
      { id: 'w-nsk', topic: 'Asia', claim: 'Japan: the newspaper association says AI training and AI search need permission.', quote: `日本新聞協会はこれまで、生成AIサービスが報道コンテンツを学習・利用する場合、報道機関の許諾を得るよう求めてきた。 … AI検索サービスでのコンテンツ利用についても権利者の許諾を得ることが原則であり`, source: at(S.wNskApril), kind: 'primary', note: 'Translation: "The association has asked that generative AI services obtain news organisations\' permission when they train on or use news content. … For the use of content in AI search services too, the principle is to obtain the rightsholder\'s permission." The article links the association\'s later statement, which says AI companies\' transparency hasn\'t improved; the permission wording is in this earlier one.' },
      { id: 'w-jp-suits', topic: 'Asia', claim: 'Japan: Nikkei and Asahi are suing Perplexity, as is Yomiuri.', quote: `Nikkei and Asahi filed their joint suit on Tuesday in Tokyo District Court … it responded to a similar suit by Japan's Yomiuri newspaper`, source: at(S.wJpSuits), kind: 'reported' },
      { id: 'w-ani', topic: 'Asia', claim: 'India: the Delhi High Court refused ANI an interim ban against OpenAI, and ANI has appealed.', quote: `the Delhi High Court today pronounced its judgment on ANI’s application seeking interim injunction against OpenAI, the developer of AI chatbot ChatGPT. Justice Amit Bansal dismissed the application`, source: at(S.wAni), kind: 'reported', note: 'The appeal: "The Delhi High Court has issued notice to OpenAI on an appeal by news agency Asian News International against a single judge’s refusal to grant it an interim injunction" (LawChakra).' },
      { id: 'w-dpiit', topic: 'Asia', claim: 'India: a government committee has proposed a mandatory training license paid into one collective.', quote: `The majority view recommends a mandatory blanket licence… … The second is a single non-profit collecting body, the Copyright Royalties Collective for AI Training (CRCAT), designated by the Central Government.`, source: at(S.wDpiit), kind: 'reported' },
      { id: 'w-linc', topic: 'Asia', claim: 'LINC, a Singapore company, enrolls Asian publishers in ILC and other licensing channels; it names no AI licensee of its own.', quote: `LINC helps Asian publishers review readiness, enroll approved websites and subdomains, and manage participation in ILC. … © IntentBridges Pte. Ltd., Singapore.`, source: at(S.wLinc), kind: 'primary', note: 'The last part is an absence: LINC\'s pages name no AI licensee of its own.' },
      { id: 'w-au-agency', topic: 'Australia', claim: 'Copyright Agency licenses business staff to use news in AI prompts; a license for AI developers is at member consultation.', quote: `In May 2025, we extended our Annual Business Licence – for businesses in sectors such as health sciences, finance, law and marketing – to allow staff to use licensed news media content in prompts for workplace AI tools. … Copyright Agency is now consulting with members on licensing their content for contextual datasets that improve outputs from AI tools or systems (e.g. via retrieval augmented generation or grounding), and developing AI models.`, source: at(S.wAuAgency), kind: 'primary' },
      { id: 'w-au-nbi', topic: 'Australia', claim: 'The new News Bargaining Incentive leaves AI answer services out.', quote: `AI firms are outside the scheme, despite training on and summarising the same journalism the law is designed to protect`, source: at(S.wAuNbi), kind: 'reported' },
      { id: 'w-ca-openai', topic: 'The Americas', claim: 'Canada: news publishers are suing OpenAI, and the Ontario court kept jurisdiction.', quote: `The Ontario Superior Court of Justice (Commercial List) confirmed jurisdiction over OpenAI Inc. and related entities in this AI and technology dispute, allowing our clients' claims to proceed.`, source: at(S.wCaOpenai), kind: 'reported', note: 'Published by the publishers\' counsel.' },
      { id: 'w-ca-anthropic', topic: 'The Americas', claim: 'Canada: news publishers are suing Anthropic.', quote: `A group of Canada’s largest publishers are suing AI company Anthropic in the Ontario court.`, source: at(S.wCaAnthropic), kind: 'reported' },
      { id: 'w-br-meta', topic: 'The Americas', claim: 'Brazil: ANJ and two other media associations won an injunction that bars Meta from using members\' content for AI training.', quote: `A Justiça de São Paulo concedeu nesta terça-feira (3) uma liminar (decisão judicial provisória urgente) à Associação Nacional de Jornais (ANJ), à Associação Brasileira de Emissoras de Rádio e Televisão (Abert) e à Associação Nacional de Editores de Revistas (Aner) em ação contra a Meta. … inclusive para treinamento comercial de modelos de inteligência artificial.`, source: at(S.wBrMeta), kind: 'reported', note: 'Translation: "The São Paulo court on Tuesday (3rd) granted an injunction (an urgent provisional ruling) to the National Newspaper Association (ANJ), the Brazilian Association of Radio and Television Broadcasters (Abert) and the National Association of Magazine Publishers (Aner) in a suit against Meta. … including for commercial training of artificial intelligence models." The injunction suspends Meta\'s new terms that would allow that use.' },
      { id: 'w-br-bill', topic: 'The Americas', claim: 'Brazil: a Senate-passed AI bill would require pay for training.', quote: `Cabe ao agente de IA que utilizar obras e conteúdos protegidos remunerar os respectivos titulares de direitos autorais e conexos pela utilização. - A remuneração pode ser negociada diretamente ou coletivamente.`, source: at(S.wBrBill), kind: 'reported', note: 'Translation: "An AI agent that uses protected works and content must pay the respective copyright and related-rights holders for the use. Pay may be negotiated directly or collectively." The article\'s title calls the bill "aprovado pelo Senado" (passed by the Senate).' },
      { id: 'w-transparency', topic: 'The closing statement', claim: 'Publishers\' associations in Europe and Asia are asking AI platforms for transparency and equal treatment.', quote: `生成AI事業者による透明性の確保が進展していないため報道コンテンツの利用実態の把握が困難であり`, source: at(S.wNskOct), kind: 'reading', note: 'Asia: the Japanese association says "because generative AI companies have made no progress on transparency, it is hard to know how news content is actually used" (quoted here). Europe: the Zurich declaration of the German-speaking publishers\' associations asks platforms to stay neutral and favor no outlet (#w-zurich).' },
      { id: 'w-zurich', topic: 'The closing statement', claim: 'The Zurich declaration of the German-speaking countries\' publishers\' associations says platforms may favor neither their own content nor that of individual outlets.', quote: Q.wZurich, source: at(S.wZurich), kind: 'reported', note: `${Q.wZurichNote} Netzwoche reports the declaration as the "Erklärung von Zürich" of "die Verlegerverbände aus dem deutschen Sprachraum".` },
    ],
  },
  {
    id: 'scorecard',
    title: 'The scorecard',
    claims: [
      // 1. Who pays you today?
      cell('pays', R1, 'ilc', 'ILC: Yahoo Scout.', Q.ilcYahoo, at(S.ilcPress), 'primary'),
      cell('pays', R1, 'prorata', 'ProRata / Gist: ProRata itself, from its own products.', Q.prTotalRevenue, at(S.prMsa, 'definitions'), 'primary'),
      cell('pays', R1, 'perplexity', 'Perplexity Comet Plus: Perplexity itself, from subscriptions.', `Comet Plus will be a $5 standalone subscription. Pro and Max subscribers get Comet Plus included in their memberships.`, at(S.comet), 'primary'),
      cell('pays', R1, 'ccc', 'CCC: no licensee named.', `No public adoption figure found.`, at(S.cccTracker, '"Adoption signals"'), 'reading', 'Absence: CCC\'s own pages name no licensee for the AI Systems Training License; a tracker reports the same.'),
      cell('pays', R1, 'cla', 'CLA / PLS: no licensee announced.', `Publishers are now being invited to opt in to the scheme.`, at(S.plsNews, '"What happens next?"'), 'reading', 'Absence: no licensee is named on CLA\'s or PLS\'s pages.'),
      cell('pays', R1, 'dpcmo', 'DPCMO: ProRata, as a test.', `Projektet er en test og vil kræve tilslutning fra en kritisk masse af danske presseudgivere.`, at(S.dpReport), 'primary', 'Translation: "The project is a test and will require a critical mass of Danish press publishers to join."'),
      cell('pays', R1, 'kopinor', 'Kopinor: the National Library, NOK 45 million a year.', Q.koPrice, at(S.koAgreement, '§17'), 'primary'),
      cell('pays', R1, 'ndp', 'NDP / GPT-NL: TNO, from GPT-NL license revenue; no paying licensee shown.', `${Q.gptOptions} … ${Q.gptRetain}`, at(S.gptRevenue), 'primary', 'No paying licensee of the model is shown (#ndp-no-payout).'),
      cell('pays', R1, 'fora', 'On FORA: no one; no collective runs on FORA yet.', undefined, at(S.fora), 'reading', 'The FORA project\'s own status.'),
      // 2. Uses
      cell('uses', R2, 'ilc', 'ILC: every AI use in each license; a publisher can exclude a licensee or a section.', Q.ilcExclude, at(S.ppa, '§2.4'), 'primary', 'Every AI use: the portal check (#ilc-uses-portal) and the agreement (#ilc-uses-agreement). A section: §2.4 lets the publisher "withdraw some or all of its Designated Content".'),
      cell('uses', R2, 'prorata', 'ProRata / Gist: answers; no training; fixed.', `providing Answers to End Users, on ProRata’s owned and operated AE Platform or through Distributed AI Search`, at(S.prMsa, '§4'), 'primary', 'No training: "Publisher content supplied to ProRata for attribution is never used for model training" (ProRata, for publishers).'),
      cell('uses', R2, 'perplexity', 'Perplexity Comet Plus: pays on visits, citations and agent actions; the publisher\'s choice of uses isn\'t stated.', `allocates revenue to our partners based on three types of internet traffic: human visits, search citations, and agent actions.`, at(S.comet), 'primary', NOT_STATED),
      cell('uses', R2, 'ccc', 'CCC: training; a publisher opts into the license.', `This license is open for your participation.`, at(S.cccSheet), 'primary', 'The license covers training and "the subsequent use of the trained system as a service" (#ccc-license).'),
      cell('uses', R2, 'cla', 'CLA / PLS: the publisher picks training or retrieval.', Q.plsUses, at(S.plsNews, '"Is the scheme mandatory?"'), 'primary'),
      cell('uses', R2, 'dpcmo', 'DPCMO: retrieval; members opt in per deal.', Q.prRagOnly, at(S.prDpcmo, '"Three Cs"'), 'primary', 'DPCMO\'s one AI deal is the ProRata framework, which is retrieval only.'),
      cell('uses', R2, 'kopinor', 'Kopinor: training only; fixed.', Q.koScope, at(S.koAgreement, '§2'), 'primary'),
      cell('uses', R2, 'ndp', 'NDP / GPT-NL: training only; fixed.', Q.gptTraining, at(S.gptProtocol), 'primary', 'Licensees of the model may not use it for "Media Integrator Services" (Annex 7).'),
      cell('uses', R2, 'fora', 'On FORA: the publisher picks, per term; a pool leaves training out.', Q.manyTerms, at(S.terms, '"Overview"'), 'primary', 'Each term carries its own use restriction. That a pool term leaves training out is the article\'s design: training on a held copy leaves no fetch record to check.'),
      // 3. Who picks (selection row)
      cell('picks', R3, 'ilc', 'ILC: the AI company; method not published.', undefined, at(S.policy), 'reading', 'Absence: ILC\'s public pages, agreement and policy were searched for "rank", "relevance", "select", "neutral", "bias", "prefer" and "steer"; none describes how a licensee picks sources (#selection-ilc-silent).'),
      cell('picks', R3, 'prorata', 'ProRata / Gist: ProRata\'s own engine; method not published.', `Answers come from your content first, with 1,600+ licensed titles behind it.`, at(S.prAnswers), 'reading', 'ProRata\'s engine picks; no selection method is published. ProRata\'s worked attribution example says "this is not a universal scoring formula".'),
      cell('picks', R3, 'perplexity', 'Perplexity Comet Plus: Perplexity\'s own engine; method not published.', `Our AI-powered answer engine rewards quality, accuracy, and relevance.`, at(S.pplxGannett), 'reading', 'A description, not a method.'),
      cell('picks', R3, 'ccc', 'CCC: the AI company, from content it already buys; method not stated.', `Organizations purchase and rely on CCC’s AI Systems Training License for rights to reuse the content they purchase or subscribe to for training AI systems.`, at(S.cccSheet), 'primary', NOT_STATED),
      cell('picks', R3, 'cla', 'CLA / PLS: the publisher chooses what to offer; the AI company\'s pick is not stated.', Q.plsUses, at(S.plsNews, '"Is the scheme mandatory?"'), 'primary', `"which content they make available" is the publisher's choice. ${NOT_STATED}`),
      cell('picks', R3, 'dpcmo', 'DPCMO: ProRata\'s engine, in the test; DPCMO\'s documents don\'t say.', Q.dpTest, at(S.dpReport), 'reading', `${Q.dpTestNote} The test runs on ProRata's Gist; DPCMO's documents say nothing about selection.`),
      cell('picks', R3, 'kopinor', 'Kopinor: the National Library "shall determine which publications are used"; method not published.', Q.koSelection, at(S.koAgreement, '§6'), 'primary'),
      cell('picks', R3, 'ndp', 'NDP / GPT-NL: you choose what to contribute; TNO filters and weights it for training, by a published rule.', `${Q.gptSelect}`, at(S.gptProtocol), 'primary', 'The weighting rule: "In the case of GPT-NL, high-quality Tokens can be repeated up to roughly 10 times for optimal performance" (Annex 6 §2.1.3). It governs the training set, not what the model draws on in an answer.'),
      cell('picks', R3, 'fora', 'On FORA: the operator\'s search; the ranking rule is the operator\'s own, and it can publish it.', Q.brokerSearch, at(S.broker), 'primary', 'The template that ranks results is the operator\'s configuration (#selection-template). FORA doesn\'t require publication.'),
      // 4. Who counts
      cell('counts', R4, 'ilc', 'ILC: the AI company, in its own report.', Q.ilcUsageFile, at(S.ilcGuide, '"How ILC licensing works"'), 'primary'),
      cell('counts', R4, 'prorata', 'ProRata / Gist: ProRata\'s attribution engine.', `“Partner Per Answer Revenue Share” means the amount of revenue allocated to Partner for a given Answer from the Answer Engine based upon the proportional contribution from Partner’s Content to such Answer`, at(S.prMsa, 'definitions'), 'primary'),
      cell('counts', R4, 'perplexity', 'Perplexity Comet Plus: Perplexity.', `allocates revenue to our partners based on three types of internet traffic: human visits, search citations, and agent actions.`, at(S.comet), 'reading', 'Perplexity allocates by traffic it observes in its own products; no outside count is described.'),
      cell('counts', R4, 'ccc', 'CCC: not stated for AI; licensee surveys in CCC\'s other licenses.', `These allocations are based on licensee surveys and other data collection activities, which are agreed to by the licensees as a condition of the license.`, at(S.cccMassDig), 'primary', 'An older CCC filing, about its annual licenses.'),
      cell('counts', R4, 'cla', 'CLA / PLS: not stated for AI; licensee reports, audits and surveys in CLA\'s other licenses.', `The allocation methodology of CLA is based on a combination of: usage reports by licensees, usage audits, surveys, and other methods as determined from time to time by the CLA Board`, at(S.plsCharter, '§4.1.1'), 'primary'),
      cell('counts', R4, 'dpcmo', 'DPCMO: ProRata\'s attribution engine.', `Publishers determine what content they provide, where it appears, and can opt-out at any time`, at(S.prDpcmo), 'reading', 'The test runs on ProRata\'s Gist Answers, "ProRata’s attribution-based, RAG-powered AI answer engine".'),
      cell('counts', R4, 'kopinor', 'Kopinor: no one; a lump sum.', `The National Library shall, subject to further agreement, provide Kopinor with access to information about the content of the dataset for distribution purposes.`, at(S.koAgreement, '§21'), 'reading', 'The fee is a fixed annual sum (§17); the library reports what the dataset contains, not how much each item is used.'),
      cell('counts', R4, 'ndp', 'NDP / GPT-NL: TNO, once: your tokens in the training set, and their quality.', Q.gptRule, at(S.gptRevenue, '§2.1.2–2.1.3'), 'primary', '"Every new GPT-NL Model with a Professional License will have its own revenue sharing calculation." Use in answers isn\'t measured.'),
      cell('counts', R4, 'fora', 'On FORA: signed fetch records, with AI companies\' reports checked against them.', Q.offerSig, ref('offer', 'Offer.signature'), 'primary', 'The AI company also signs its acceptance (TransactionItem.agent_acceptance). Checking reports against the records is the operator\'s job in the article\'s design.'),
      // 5. Split rule
      cell('split', R5, 'ilc', 'ILC: principles; the calculations "are not publicly disclosed".', Q.ilcNotDisclosed, at(S.policy, '§1'), 'primary'),
      cell('split', R5, 'prorata', 'ProRata / Gist: the formula, not the attribution weights.', Q.prFormula, at(S.prMsa, 'definitions'), 'primary', 'On the weights, ProRata\'s own worked example says "this is not a universal scoring formula" (How it works).'),
      cell('split', R5, 'perplexity', 'Perplexity Comet Plus: three categories of traffic.', `allocates revenue to our partners based on three types of internet traffic: human visits, search citations, and agent actions.`, at(S.comet), 'primary', 'Payouts aren\'t disclosed: "we are not disclosing any of those numbers" (Digiday interview with Perplexity\'s head of publisher partnerships).'),
      cell('split', R5, 'ccc', 'CCC: no.', `Rightsholders receive royalty distributions electronically from CCC.`, at(S.cccSheet), 'reading', 'Absence: no distribution rule for the AI license appears on CCC\'s pages.'),
      cell('split', R5, 'cla', 'CLA / PLS: general splits; no AI rule yet.', `Journals 76.00 23.00 1.00`, at(S.plsCharter, 'revenue shares table'), 'primary', 'One row of the published table of shares for standard licenses. No AI-specific rule is published.'),
      cell('split', R5, 'dpcmo', 'DPCMO: not online.', `vedtog foreningen på generalforsamlingen i 2024 en midlertidig fordelingspolitik for 2024- 2025. Fordelingen afventer afklaring med autorerne.`, at(S.dpReport), 'reading', 'Translation: "the association adopted a temporary distribution policy for 2024–2025 at its 2024 general assembly. Distribution awaits clarification with the authors." The policy itself was not found online.'),
      cell('split', R5, 'kopinor', 'Kopinor: general guidelines; the split among newspapers not found.', `Vederlag til rettighetshaverne fordeles etter retningslinjer som er vedtatt av Kopinors representantskap.`, at(S.koAnnual, '§9.1'), 'primary', 'Translation: "Remuneration to rightsholders is distributed under guidelines adopted by Kopinor\'s council of representatives." How MBL splits the AI money among newspapers was not found.'),
      cell('split', R5, 'ndp', 'NDP / GPT-NL: yes, in TNO\'s template: token count times a quality multiplier.', Q.gptShare, at(S.gptRevenue, '§2.1'), 'primary', `The two factors: "${Q.gptRule.replace(' … ', '" and "')}" (§2.1.2–2.1.3).`),
      cell('split', R5, 'fora', 'On FORA: every weight and threshold is published.', undefined, at(S.fora), 'reading', 'The article\'s design: the allocation rule is part of the pool\'s published terms; the protocol carries none.'),
      // 6. Operator's cut
      cell('keeps', R6, 'ilc', 'ILC: its costs, "projected at or below 10%".', `After operating expenses, projected at or below 10% and consistent with comparable collective licensing organizations, the remaining revenue passes directly to rights holders.`, at(S.ilcPress), 'primary', 'A projection: the agreement\'s costs include "reasonable reserves for anticipated operating expenses and obligations" (§1.1(a)), with no ceiling.'),
      cell('keeps', R6, 'prorata', 'ProRata / Gist: 50%.', Q.prPool, at(S.prMsa, 'definitions'), 'primary'),
      cell('keeps', R6, 'perplexity', 'Perplexity Comet Plus: "a small portion"; 20% in press reports.', `Perplexity keeps 20% of it, and the other 80% will go to participants in Perplexity’s publisher program.`, at(S.pplxDigiday), 'reported', 'Perplexity\'s own words: "minus a small portion for Perplexity’s compute costs".'),
      cell('keeps', R6, 'ccc', 'CCC: not published.', undefined, at(S.cccSheet), 'reading', NOT_STATED),
      cell('keeps', R6, 'cla', 'CLA / PLS: 11% (CLA) and 6% (PLS) on standard licenses; not stated for AI.', `CLA deducts an administration fee, prior to distribution to the CMOs as set out in paragraph 2.2 above, of: 3.1.1 11% in the case of revenue collected from all licences … an administration fee of 6%.`, at(S.plsCharter, '§3.1, §3.3'), 'primary', 'The charter predates the AI license; whether these fees apply to AI revenue is not stated.'),
      cell('keeps', R6, 'dpcmo', 'DPCMO: not published.', undefined, at(S.dpReport), 'reading', `${NOT_STATED} No deduction for AI money is published.`),
      cell('keeps', R6, 'kopinor', 'Kopinor: not published for this money.', Q.koPaid, at(S.koPayout), 'reading', `${NOT_STATED} The release reports the payout to MBL, with no deduction for the AI money.`),
      cell('keeps', R6, 'ndp', 'NDP / GPT-NL: 50%, re-invested in the model.', `${Q.gptRetain}`, at(S.gptRevenue), 'primary', 'The template: "TNO’s share of the Net Revenues will be re-invested to cover cost of the further development and maintenance of the GPT-NL Model and the Research Facility" (#ndp-reinvested).'),
      cell('keeps', R6, 'fora', 'On FORA: the operator sets its cut and publishes it.', `A revenue share has no price at transaction time: its rate and its settlement are an agreement between the agent and the publisher outside this protocol.`, at(S.terms, '"Revenue-share arrangements"'), 'reading', 'The article\'s design: the cut is part of the pool\'s published terms.'),
      // 7. Regulated, vote
      cell('governance', R7, 'ilc', 'ILC: not regulated; no member vote; a publisher steering committee.', Q.ilcNoVote, at(S.ppa, '§2.1'), 'primary', 'The committee: "The ILC Publisher Steering Committee oversees the licensing framework, safeguards, and economics of the collective" (FAQ); the policy calls its role "advisory" (§13.1). Not regulated: ILC is "a Tennessee nonprofit corporation", and no US statute regulates a voluntary collective (a reading).'),
      cell('governance', R7, 'prorata', 'ProRata / Gist: a private company; no vote.', `ProRata reserves the right to modify this Agreement from time to time, by updating these terms as posted online and/or in the applicable ProRata Offerings.`, at(S.prMsa, '"Amendment"'), 'primary'),
      cell('governance', R7, 'perplexity', 'Perplexity Comet Plus: a private company; no vote found.', `Through this strategic content licensing agreement, premium journalism from USA TODAY and the USA TODAY Network's 200+ local publications will be integrated into Perplexity's AI-powered search experiences.`, at(S.pplxGannett), 'reading', 'Perplexity\'s publisher deals are bilateral agreements; no governance role for publishers was found.'),
      cell('governance', R7, 'ccc', 'CCC: not regulated; no vote found.', `CCC (Copyright Clearance Center), a pioneer in voluntary collective licensing`, at(S.cccPress), 'reading', 'The US has no statute regulating collectives; no rightsholder vote is described on CCC\'s pages.'),
      cell('governance', R7, 'cla', 'CLA / PLS: regulated; publishers vote through trade associations.', Q.plsRegulated, at(S.plsReport, '"Compliance and code of conduct"'), 'primary', 'PLS\'s governance page: "Owned and directed by: Association of Learned and Professional Society Publishers" and other trade associations.'),
      cell('governance', R7, 'dpcmo', 'DPCMO: regulated; members vote.', Q.dpAssembly, at(S.dpReport, 'page 4'), 'primary', `${Q.dpAssemblyNote} Regulated: #dpcmo-regulated.`),
      cell('governance', R7, 'kopinor', 'Kopinor: regulated; member organizations vote.', Q.koRegulated, at(S.koAnnual), 'primary', `${Q.koRegulatedNote} Its distribution guidelines are adopted by its council of representatives (§9.1).`),
      cell('governance', R7, 'ndp', 'NDP / GPT-NL: not regulated; no direct vote; a contributors\' Content Board.', `that may have a substantial negative impact on the protection provided to Content Contributors under the Content Contributor Agreement, may only be taken with the agreement of the member on behalf of the Content Board, which will not be unreasonably withheld.`, at(S.gptCharter, '§2.5.3.4'), 'primary', 'TNO decides; the Content Board\'s member must agree to changes that weaken contributor protections. NDP is a trade association and TNO a public research body; neither is a regulated collective (a reading).'),
      cell('governance', R7, 'fora', 'On FORA: not regulated; each operator sets its governance.', undefined, at(S.fora), 'reading', 'FORA is a protocol; it defines no governance for a pool.'),
      // 8. Earlier copies
      cell('held', R8, 'ilc', 'ILC: yes.', Q.ilcHeld, at(S.ilcGuide, '"What an RSL declaration does"'), 'primary', 'ILC\'s enforcement mandate starts at designation: "occurring on or after the date such Content became Designated Content" (agreement §5.4(g)).'),
      cell('held', R8, 'prorata', 'ProRata / Gist: no; retrieval only.', Q.prRagOnly, at(S.prDpcmo, '"Three Cs"'), 'primary'),
      cell('held', R8, 'perplexity', 'Perplexity Comet Plus: not stated.', undefined, at(S.comet), 'reading', NOT_STATED),
      cell('held', R8, 'ccc', 'CCC: not stated.', undefined, at(S.cccSheet), 'reading', NOT_STATED),
      cell('held', R8, 'cla', 'CLA / PLS: no; "No retrospective cover".', `No retrospective cover`, at(S.plsFlyer, '"GenAI Product Licensing"'), 'primary', 'The flyer\'s layout makes the column assignment slightly ambiguous.'),
      cell('held', R8, 'dpcmo', 'DPCMO: no; it is suing OpenAI over it.', Q.dpOpenai, at(S.dpOpenai), 'primary'),
      cell('held', R8, 'kopinor', 'Kopinor: the library\'s own collections, yes; earlier training of its base models, no.', `har Nasjonalbiblioteket og Kopinor blitt enige om vilkårene for å benytte Nasjonalbibliotekets samlinger av beskyttede publikasjoner til slik maskinlæring.`, at(S.koTraining), 'primary', `Translation: "the National Library and Kopinor have agreed the terms for using the National Library's collections of protected publications for such machine learning." The agreement: "${Q.koPretraining.split('. ')[1]}" (§11).`),
      cell('held', R8, 'ndp', 'NDP / GPT-NL: no; it covers GPT-NL\'s own training only.', Q.gptTraining, at(S.gptProtocol), 'reading', 'The license is to TNO for training GPT-NL; it says nothing about other developers\' earlier copies. Open Future: "GPT-NL trains only on data it has positive authorization to use".'),
      cell('held', R8, 'fora', 'On FORA: no; a copy already held leaves no record to check.', Q.offerSig, ref('offer', 'Offer.signature'), 'reading', 'FORA records each fetch it brokers. A model trained on a copy it already holds makes no fetch.'),
      {
        id: 'sc-non-exclusive', topic: 'Under the table',
        claim: 'Six of the eight say participation is non-exclusive.',
        quote: Q.ilcFaqExclusive, source: at(S.ilcFaq, '"Is participation exclusive?"'), kind: 'primary',
        note: 'ILC (quoted). ProRata: "No. It is non-exclusive and fits alongside anything else in your AI strategy" (Gist Answers). CCC: "a voluntary, non-exclusive collective license". PLS: "the non-exclusive right for PLS" (terms and conditions §3.2). DPCMO: "Participation is free and non-exclusive". GPT-NL: "The Content Contributor may license the Contributor Training Content to third parties at its discretion" (template agreement). Perplexity and Kopinor don\'t say.',
      },
    ],
  },
  {
    id: 'adds',
    title: 'What FORA adds',
    claims: [
      { id: 'adds-lead', claim: 'No scheme\'s public documents offer the points below.', source: at(S.scorecard), kind: 'reading', note: 'Based on the scorecard rows "Who counts", "Is the split rule published?" and the statements under #adds-statements, across the eight schemes.' },
      { id: 'adds-record-schemes', claim: 'In the six schemes that say how use is counted, the AI company reports its own use, the operator or the licensee counts it, or no one counts per use; CCC and CLA haven\'t said for AI.', quote: Q.ilcUsageFile, source: at(S.ilcGuide, '"How ILC licensing works"'), kind: 'reading', note: 'Basis: the scorecard row "Who counts the use your share rests on?" (#sc-counts-ilc to #sc-counts-ndp). ILC: the AI company. ProRata and DPCMO: ProRata\'s engine. Perplexity: its own traffic. NDP: TNO, the licensee. Kopinor: a lump sum.' },
      { id: 'adds-record-fora', claim: 'On FORA, every fetch is a transaction for one URL; the operator\'s Exchange signs the offer, and the AI company signs its acceptance.', quote: Q.acceptance, source: ref('transactionitem', 'TransactionItem.agent_acceptance'), kind: 'primary', note: 'The Exchange\'s signature covers the entire offer (Offer.signature, #journey-counted-fora).' },
      { id: 'adds-audit-only', claim: 'The schemes\' public terms offer at most an audit or a dispute right.', quote: `Partner may request to have an independent third party confidentially inspect the Records if it reasonably disputes Revenue Share paid under this Agreement.`, source: at(S.prMsa, '§6'), kind: 'reading', note: 'ProRata allows an inspection in a dispute; ILC says it "supports auditing of license compliance" (publishers page); CLA\'s general method includes "usage audits". No scheme describes checking each report against a record it didn\'t get from the payer.' },
      { id: 'adds-reconcile', claim: 'On FORA, the operator reconciles each AI company\'s report with the fetch records before it splits the pool.', quote: `The agent reports what it consumed, not what it estimated: an Exchange MUST NOT refuse a report because this differs from the estimate, in either direction.`, source: ref('usagereport', 'UsageReport.consumed_quantity'), kind: 'reading', note: 'The protocol binds each report to its transaction; the reconciliation is the operator\'s job in the article\'s design.' },
      { id: 'adds-recompute-seven', claim: 'Seven of the eight don\'t publish enough to redo the sum.', quote: Q.ilcNotDisclosed, source: at(S.policy, '§1'), kind: 'reading', note: 'Basis: the scorecard row "Is the split rule published?" (#sc-split-ilc to #sc-split-ndp).' },
      { id: 'adds-recompute-gptnl', claim: 'GPT-NL publishes its rule; its public documents don\'t say whether a contributor gets the token counts and quality scores the sum needs.', quote: Q.gptShare, source: at(S.gptRevenue, '§2.1'), kind: 'reading', note: 'The rule is published (#sc-split-ndp). Absence: no contributor statement or report of token counts and scores was found; the agreement itself is confidential (template §11).' },
      { id: 'adds-recompute-fora', claim: 'On FORA, your statement gives your weight, the total weight, the pool, the operator\'s cut and the version of the rule.', source: at(S.fora), kind: 'reading', note: 'The article\'s design for the operator\'s statement.' },
      { id: 'adds-statements', claim: 'ProRata sends monthly statements down to the article; ILC sends periodic ones and makes them confidential; none promises data per fetch.', quote: `ProRata will deliver to Partner (including by making available to partner a web-based access to the information) a statement of Partner Revenue Share for the preceding month`, source: at(S.prMsa, '§6, "Reporting"'), kind: 'primary', note: 'ProRata\'s statement goes to "Partner-level", publication and article detail. ILC: "ILC shall provide Publisher with periodic royalty statements through the Platform" (§4.1), and statements are "confidential information of ILC" (§7.5). "None promises data per fetch" is an absence across the eight.' },
      { id: 'adds-own-data', claim: 'On FORA, you see each of your transactions, and the report filed against it, as it arrives.', quote: Q.offerSig, source: ref('offer', 'Offer.signature'), kind: 'reading', note: 'The protocol creates a record per transaction; showing it to the publisher as it arrives is the operator\'s dashboard in the article\'s design.' },
      { id: 'adds-own-terms', claim: 'Your own priced terms beside the pool\'s: join the pool with one term for everything, or a term per section and per use; terms you price yourself run next to it, and the same fetch records back both.', quote: Q.manyTerms, source: at(S.terms, '"Overview"'), kind: 'primary' },
      { id: 'adds-limit', claim: 'A record proves the fetch; what a model did with the page afterward comes from the AI company\'s report, and an audit checks it.', quote: Q.offerSig, source: ref('offer', 'Offer.signature'), kind: 'reading', note: 'The signatures cover what was offered and accepted for one fetch. Use inside the model leaves no record outside the AI company.' },
    ],
  },
  {
    id: 'selection',
    title: 'Who decides which publisher gets used',
    claims: [
      { id: 'selection-none', claim: 'No scheme publishes how an AI system picks whose content to use in an answer.', source: at(S.scorecard), kind: 'reading', note: 'Absence, across the scorecard row "Who picks whose content gets used" and the "Around the world" panel (#w-transparency).' },
      { id: 'selection-fee-same', claim: 'An AI company pays the same fee whichever publisher its system picks, so the split between publishers follows the pick.', quote: `AI companies track when your content is used, whether for grounding, citation, or other uses that help shape the output.`, source: at(S.ilcPublishers), kind: 'reading', note: 'A share measured from the licensee\'s use rises and falls with the licensee\'s choices; the fee is set by the license.' },
      { id: 'selection-prorata-engine', claim: 'ProRata\'s own engine chooses the sources.', quote: `Answers come from your content first, with 1,600+ licensed titles behind it.`, source: at(S.prAnswers), kind: 'primary' },
      { id: 'selection-perplexity-engine', claim: 'Perplexity\'s own engine chooses the sources.', quote: `Our AI-powered answer engine rewards quality, accuracy, and relevance.`, source: at(S.pplxGannett), kind: 'primary' },
      { id: 'selection-ilc-silent', claim: 'ILC\'s public pages, its agreement and its policy don\'t say how a licensee chooses.', source: at(S.policy), kind: 'reading', note: 'Based on absence: ILC\'s public pages, the agreement and the policy were searched for "rank", "relevance", "select", "neutral", "bias", "prefer" and "steer". The only hit near the topic is the policy\'s principle "Apply Consistent, Content-Neutral Standards" (§3), which governs ILC\'s own allocation, not the AI system\'s choice of sources.' },
      { id: 'selection-gptnl', claim: 'GPT-NL comes closest, for training only: it publishes how TNO filters and weights each contributor\'s text.', quote: `In the case of GPT-NL, high-quality Tokens can be repeated up to roughly 10 times for optimal performance.`, source: at(S.gptRevenue, '§2.1.3'), kind: 'primary', note: 'On overlap: "the data for which a Content Contributor Agreement was signed latest, will get deleted" (§2.1.2). This weights the training set; it isn\'t an answer-time rule.' },
      { id: 'selection-kopinor', claim: 'One contract names the picker: the National Library.', quote: Q.koSelection, source: at(S.koAgreement, '§6'), kind: 'primary' },
      { id: 'selection-operator-search', claim: 'On FORA, the operator runs the search.', quote: Q.brokerSearch, source: at(S.broker), kind: 'primary', note: 'For Elasticsearch: "The Broker runs the operator\'s search template against an existing index the operator points it at. It does not interpret the query, and it calls no model."' },
      { id: 'selection-template', claim: 'The operator writes the ranking rule, so the collective holds it and can publish it.', quote: `The query is configuration, not code. … The template, stored in the cluster (Config.TemplateID) or sent with every search (Config.TemplateSource), decides which fields are searched, how they rank and how each filter applies.`, source: at(S.essearch, 'src/broker/internal/essearch/doc.go'), kind: 'primary', note: 'FORA Server\'s Elasticsearch catalog search. FORA Server isn\'t a public repository, so there is no URL. FORA doesn\'t require the operator to publish the template.' },
      { id: 'selection-gutefrage', claim: 'Gutefrage, which runs FORA on helpster.de, uses the Elasticsearch search engine.', quote: `Gutefrage, as an implementor, chooses to have Elasticsearch`, source: at(S.implementer), kind: 'primary', note: 'Implementer information given to the FORA project; no public URL.' },
      { id: 'selection-per-url', claim: 'The search only proposes URLs: each fetch is licensed on its publisher\'s terms.', quote: `Elasticsearch supplies candidate URLs and nothing else. Every URL then takes the Broker's normal per-URL route (publisher manifest, Exchange discovery, offer verification), so a stale hit cannot produce an offer the Exchange does not stand behind.`, source: at(S.essearch, 'src/broker/internal/essearch/doc.go'), kind: 'primary', note: 'A catalog entry names one resource by its domain and exact path (ResourceEntry, /reference/proto-fora/#resourceentry).' },
      { id: 'selection-recorded', claim: 'Each fetch is recorded as its own transaction for one resource.', quote: `each item is atomic, and its integrity is per resource. Each offer carries the signature of the Exchange that issued it, covering price, terms, expiry and \`exchange\`; each item carries the agent's acceptance of that one offer`, source: ref('transactionitem', 'TransactionItem'), kind: 'primary' },
      { id: 'selection-model-cites', claim: 'The AI company\'s model still decides what to cite.', source: at(S.fora), kind: 'reading', note: 'The search proposes URLs and the Exchange signs offers for them; what the AI system then grounds on and cites happens inside its model, which the operator doesn\'t control.' },
    ],
  },
  {
    id: 'ahead',
    title: 'Where others are ahead of FORA',
    claims: [
      { id: 'ahead-ilc-licensee', topic: 'They run, and some pay', claim: 'ILC has a licensee in Yahoo Scout.', quote: Q.ilcYahoo, source: at(S.ilcPress), kind: 'primary' },
      { id: 'ahead-prorata-shares', topic: 'They run, and some pay', claim: 'ProRata shares revenue with its partners under a public agreement.', quote: Q.prPool, source: at(S.prMsa, 'definitions'), kind: 'primary' },
      { id: 'ahead-kopinor-paid', topic: 'They run, and some pay', claim: 'Kopinor has paid NOK 44.1 million to MBL.', quote: Q.koPaid, source: at(S.koPayout), kind: 'primary', note: Q.koPaidNote },
      { id: 'ahead-none-on-fora', topic: 'They run, and some pay', claim: 'No collective runs on FORA yet.', source: at(S.fora), kind: 'reading', note: 'The FORA project\'s own status.' },
      { id: 'ahead-regulated', topic: 'A legal mandate, and enforcement', claim: 'CLA, PLS, DPCMO and Kopinor are regulated: the law sets what they must disclose, and a supervisor oversees them.', quote: Q.plsRegulated, source: at(S.plsReport, '"Compliance and code of conduct"'), kind: 'primary', note: 'DPCMO: #dpcmo-regulated. Kopinor: "Kopinor er omfattet av lov om kollektiv forvaltning av opphavsrett mv. og står under tilsyn av Patentstyret." (Kopinor is covered by the act on collective management of copyright and is supervised by the Norwegian Industrial Property Office; Kopinor annual report.)' },
      { id: 'ahead-dpcmo-suing', topic: 'A legal mandate, and enforcement', claim: 'DPCMO is suing OpenAI.', quote: Q.dpOpenai, source: at(S.dpOpenai), kind: 'primary' },
      { id: 'ahead-ilc-attorney', topic: 'A legal mandate, and enforcement', claim: 'ILC\'s participation agreement lets it sue unlicensed AI companies in a publisher\'s name.', quote: `to bring such proceedings in the name of Publisher, in the name of ILC, or in the name of such other person, as applicable law permits`, source: at(S.ppa, '§5.4(c)'), kind: 'primary', note: 'The same clause appoints ILC "as Publisher’s true and lawful attorney-in-fact".' },
      { id: 'ahead-fora-no-mandate', topic: 'A legal mandate, and enforcement', claim: 'FORA is a protocol: it has no mandate, and it takes no one to court.', source: at(S.fora), kind: 'reading', note: 'FORA defines a wire format; enforcement is left to the parties.' },
      { id: 'ahead-ilc-held', topic: 'Copies AI companies already hold', claim: 'ILC\'s license reaches content that AI companies already hold, "acquired before the RSL declaration was published".', quote: Q.ilcHeld, source: at(S.ilcGuide, '"What an RSL declaration does"'), kind: 'primary' },
      { id: 'ahead-rsl', topic: 'Copies AI companies already hold', claim: 'RSL is the format ILC uses for that declaration.', quote: `The ILC licensing platform uses the open RSL (Really Simple Licensing) standard to enable publishers specify which content is available for AI licensing.`, source: at(S.ilcFaq, '"How is the ILC related to RSL?"'), kind: 'primary' },
      { id: 'ahead-training-licensed', topic: 'Copies AI companies already hold', claim: 'CCC, CLA, Kopinor and NDP license training.', quote: Q.cccLicense, source: at(S.cccSheet), kind: 'primary', note: 'CLA: "training and fine tuning" (#cla-uses). Kopinor: #kopinor-scope. NDP: #sc-uses-ndp.' },
      { id: 'ahead-fora-no-held', topic: 'Copies AI companies already hold', claim: 'A pool on FORA licenses what leaves a fetch record, and a model trained on a copy it already holds leaves none.', quote: Q.offerSig, source: ref('offer', 'Offer.signature'), kind: 'reading', note: 'See #sc-held-fora.' },
      { id: 'ahead-dpcmo-assembly', topic: 'A vote', claim: 'DPCMO\'s members vote in a general assembly.', quote: Q.dpAssembly, source: at(S.dpReport, 'page 4'), kind: 'primary', note: Q.dpAssemblyNote },
      { id: 'ahead-fora-governance', topic: 'A vote', claim: 'FORA leaves governance to each operator.', source: at(S.fora), kind: 'reading', note: 'The protocol defines no governance for a pool.' },
      { id: 'ahead-fora-pool-term', topic: 'Excluding one AI company', claim: 'On FORA, the operator admits AI companies to the pool, and a publisher\'s pool term covers each one it admits.', quote: `Scope-gating: the Exchange presents an offer for this term only when the scopes in the requester's signed request (Requester.scopes) cover ALL of these scopes (AND-semantics). Empty = public. A subscription term is Pricing{model:FREE} + scopes:["subscription:..."].`, source: ref('licenseterm', 'LicenseTerm.scopes'), kind: 'primary', note: 'The operator grants the pool\'s scope to the AI companies it admits; the publisher\'s pool term is presented to any agent holding it.' },
    ],
  },
  {
    id: 'faq',
    title: 'Questions publishers ask',
    claims: [
      { id: 'faq-cost', claim: 'FORA is free; each collective chooses how it prices its service.', quote: `FORA is free. Each collective chooses how it prices its service.`, source: at(S.fora), kind: 'primary', note: 'The FORA project\'s statement.' },
      { id: 'faq-keep-one-out', claim: 'A publisher keeps one AI company out by scoping its terms to the AI companies it licenses; any it leaves out get no offer.', quote: `For a term the Exchange gates behind a delegation, it presents the term only when a verified delegation grants those scopes`, source: at(S.terms, 'Licensing terms, opening section'), kind: 'primary', note: 'A term is presented only to requesters whose verified delegation grants its scopes, so an AI company outside those scopes gets no offer for it.' },
      { id: 'faq-money', claim: 'The operator collects the fees and pays publishers through its own payment provider; the protocol signs and records, and never moves money.', quote: Q.money, source: at(S.money, '"The Billing Chain"'), kind: 'primary' },
      { id: 'faq-ilc-allows', claim: 'ILC allows a publisher to join a collective on FORA as well.', quote: Q.ilcFaqExclusive, source: at(S.ilcFaq, '"Is participation exclusive?"'), kind: 'primary' },
      { id: 'faq-exclude-first', claim: 'If you want an ILC licensee to pay through a FORA collective, exclude it in ILC first.', quote: Q.ilcExclude, source: at(S.ppa, '§2.4'), kind: 'reading', note: 'The portal check requires a declaration that grants every AI use (#ilc-uses-portal), so the same AI company would otherwise hold a license for the same uses twice. Exclusion in ILC is per AI company.' },
      { id: 'faq-no-training', claim: 'A collective on FORA doesn\'t license training: the pool licenses uses that start with a fetch, and a model that trains on a copy it holds fetches nothing.', quote: Q.offerSig, source: ref('offer', 'Offer.signature'), kind: 'reading', note: 'The article\'s design for a pool; see #sc-held-fora.' },
      { id: 'faq-own-training', claim: 'You can still license training on your own priced term.', quote: Q.manyTerms, source: at(S.terms, '"Overview"'), kind: 'primary', note: 'A term\'s use restriction can permit training ("What the agent may do with the resource", "Restrictions"); a priced term sits beside the pool term on the same resource.' },
      { id: 'faq-why-join', claim: 'An AI company outside the collective meets a per-fetch price or a block at each member\'s pages.', quote: `A publisher's edge that refuses a request for licensed content carrying no valid signed URL answers \`403\` and SHOULD send \`X-Content-Rules\`, the absolute URL of the publisher's manifest`, source: at(S.proto, '"Edge discovery headers"'), kind: 'primary', note: 'The manifest lists the Exchanges that sell the content. One license to many publishers and one report format are the collective\'s design, as the article describes it.' },
      { id: 'faq-no-law', claim: 'No law makes an AI company join a collective.', quote: Q.cccLicense, source: at(S.cccSheet), kind: 'reading', note: 'The collective AI licenses in this field are voluntary: CCC\'s is "voluntary", and PLS says "The scheme is entirely voluntary and opt-in". India\'s committee has only proposed a mandatory license (#w-dpiit). Unlike the US compulsory license for music (see /resources/music-dsp/), no statute found compels an AI company to take one.' },
    ],
  },
];
