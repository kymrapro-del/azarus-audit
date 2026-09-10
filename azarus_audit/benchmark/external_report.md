# Evaluation externe du scanner (donnees publiques reelles)

- Source : `CyberNative/Code_Vulnerability_Security_DPO (Python)` (Hugging Face)
- Echantillons Python : 274 vulnerables + 274 surs

## Toutes severites
- Detection : **205/274 = 74.8%**
- Faux positifs : **153/274 = 55.8%** (majorant)

## Tier actionnable (severite critique + eleve)
- Detection : **195/274 = 71.2%**
- Faux positifs : **145/274 = 52.9%** (majorant)

> Le code "sur" n'est corrige que pour une faille precise ; il peut
> contenir d'autres motifs risquables. Le taux de faux positifs est donc
> un majorant. Reproductible : `python -m azarus_audit.benchmark.external`.
