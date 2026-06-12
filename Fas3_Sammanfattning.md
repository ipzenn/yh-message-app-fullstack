Fas 3 Sammanfattning av säkerhetsgranskning

Metod
Tre verktyg användes: CodeQL (statisk kodanalys), Dependabot (beroendeanalys) och AI-kodgranskning (flödesanalys). 
Det fanns även som default en secret scanning i github som scannade kodbase för nycklar och andra hemliga grejer som gav 0 utslag.

Fynd
CodeQL – 8 varningar: 7 endpoints saknar rate limiting, 1 CORS wildcard (origin: "*")
Dependabot – 16 varningar: jsonwebtoken har 3 CVE:er inkl. signaturvalideringsbypass. Node-tar och launch-editor har kritiska path traversal- och command injection-sårbarheter.
AI-granskning – 10 fynd bland annat att DELETE-routen saknar autentisering, JWT läcker till console.log, övertydliga felmeddelanden möjliggör user enumeration


Kombinationsrisker
De enskilda bristerna förstärker varandra: 
1. Oskyddad DELETE + CORS wildcard + avsaknad av rate limiting möjliggör massradering av databasinnehåll utan inloggning. 

2. User enumeration + ingen rate limiting möjliggör credential stuffing. JWT-läckage + sårbara jsonwebtoken-versioner komprometterar autentiseringen.

Slutsats
Applikationen bör inte driftsättas i sin nuvarande form. Tre åtgärder är akuta: lägg till autentisering på DELETE-routen, ta bort console.log med JWT-token, och uppgradera jsonwebtoken till v9.0.0+. Vi förstod vikten av att använda flera verktyg som komplement till varandra för att fånga upp fler sårbarheter och kunna prioritera dessa. För varje verktyg som används så utökas chansen att hitta sårbarheter men vi såg även nyttan med att kombinera dem för att förstå hur omfattande en skada faktiskt kan bli. Samt att man som företag sätter upp rutiner för hur dem ska arbete med sånna här scans. och hur viktigt det är att förstå att säkerhetsarbetet aldrig är klart. Nya sårbarheter upptäcks löpande i paket vi redan använder idag. Därför behöver säkerhetsskanning vara ett kontinuerligt flöde, inte något man bara gör en gång.