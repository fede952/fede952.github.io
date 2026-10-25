// Metric and value names for the CVSS calculator UI. English names are FIRST's
// (v4.0: cvss_config.js of the official calculator; v3.1: the specification).
// Other languages translate the English phrase; T[lang][phrase] falls back to English.

export const V4_GROUPS = [
  { id: 'base', name: 'Base Metrics', open: true, sub: [
    ['Exploitability Metrics', ['AV', 'AC', 'AT', 'PR', 'UI']],
    ['Vulnerable System Impact Metrics', ['VC', 'VI', 'VA']],
    ['Subsequent System Impact Metrics', ['SC', 'SI', 'SA']],
  ] },
  { id: 'threat', name: 'Threat Metrics', sub: [['', ['E']]] },
  { id: 'envreq', name: 'Environmental (Security Requirements)', sub: [['', ['CR', 'IR', 'AR']]] },
  { id: 'envmod', name: 'Environmental (Modified Base Metrics)', sub: [
    ['Exploitability Metrics', ['MAV', 'MAC', 'MAT', 'MPR', 'MUI']],
    ['Vulnerable System Impact Metrics', ['MVC', 'MVI', 'MVA']],
    ['Subsequent System Impact Metrics', ['MSC', 'MSI', 'MSA']],
  ] },
  { id: 'supp', name: 'Supplemental Metrics', sub: [['', ['S', 'AU', 'R', 'V', 'RE', 'U']]] },
];

const X = ['X', 'Not Defined'];
const HLN = [['H', 'High'], ['L', 'Low'], ['N', 'None']];
const HLNeg = [X, ['H', 'High'], ['L', 'Low'], ['N', 'Negligible']];
const SHLNeg = [X, ['S', 'Safety'], ['H', 'High'], ['L', 'Low'], ['N', 'Negligible']];
const REQ = [X, ['H', 'High'], ['M', 'Medium'], ['L', 'Low']];
const AV4 = [['N', 'Network'], ['A', 'Adjacent'], ['L', 'Local'], ['P', 'Physical']];

export const V4_METRICS = {
  AV: ['Attack Vector', AV4], AC: ['Attack Complexity', [['L', 'Low'], ['H', 'High']]], AT: ['Attack Requirements', [['N', 'None'], ['P', 'Present']]],
  PR: ['Privileges Required', [['N', 'None'], ['L', 'Low'], ['H', 'High']]], UI: ['User Interaction', [['N', 'None'], ['P', 'Passive'], ['A', 'Active']]],
  VC: ['Confidentiality', HLN], VI: ['Integrity', HLN], VA: ['Availability', HLN], SC: ['Confidentiality', HLN], SI: ['Integrity', HLN], SA: ['Availability', HLN],
  E: ['Exploit Maturity', [X, ['A', 'Attacked'], ['P', 'POC'], ['U', 'Unreported']]],
  CR: ['Confidentiality Requirements', REQ], IR: ['Integrity Requirements', REQ], AR: ['Availability Requirements', REQ],
  MAV: ['Attack Vector', [X, ...AV4]], MAC: ['Attack Complexity', [X, ['L', 'Low'], ['H', 'High']]], MAT: ['Attack Requirements', [X, ['N', 'None'], ['P', 'Present']]],
  MPR: ['Privileges Required', [X, ['N', 'None'], ['L', 'Low'], ['H', 'High']]], MUI: ['User Interaction', [X, ['N', 'None'], ['P', 'Passive'], ['A', 'Active']]],
  MVC: ['Confidentiality', [X, ...HLN]], MVI: ['Integrity', [X, ...HLN]], MVA: ['Availability', [X, ...HLN]],
  MSC: ['Confidentiality', HLNeg], MSI: ['Integrity', SHLNeg], MSA: ['Availability', SHLNeg],
  S: ['Safety', [X, ['N', 'Negligible'], ['P', 'Present']]], AU: ['Automatable', [X, ['N', 'No'], ['Y', 'Yes']]],
  R: ['Recovery', [X, ['A', 'Automatic'], ['U', 'User'], ['I', 'Irrecoverable']]], V: ['Value Density', [X, ['D', 'Diffuse'], ['C', 'Concentrated']]],
  RE: ['Vulnerability Response Effort', [X, ['L', 'Low'], ['M', 'Moderate'], ['H', 'High']]],
  U: ['Provider Urgency', [X, ['Clear', 'Clear'], ['Green', 'Green'], ['Amber', 'Amber'], ['Red', 'Red']]],
};

export const V31_GROUPS = [
  { id: 'base', name: 'Base Metrics', open: true, sub: [['Exploitability Metrics', ['AV', 'AC', 'PR', 'UI']], ['Scope', ['S']], ['Impact Metrics', ['C', 'I', 'A']]] },
  { id: 'temporal', name: 'Temporal Metrics', sub: [['', ['E', 'RL', 'RC']]] },
  { id: 'envreq', name: 'Environmental (Security Requirements)', sub: [['', ['CR', 'IR', 'AR']]] },
  { id: 'envmod', name: 'Environmental (Modified Base Metrics)', sub: [['', ['MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA']]] },
];
const AV3 = [['N', 'Network'], ['A', 'Adjacent Network'], ['L', 'Local'], ['P', 'Physical']];
export const V31_METRICS = {
  AV: ['Attack Vector', AV3], AC: ['Attack Complexity', [['L', 'Low'], ['H', 'High']]], PR: ['Privileges Required', [['N', 'None'], ['L', 'Low'], ['H', 'High']]],
  UI: ['User Interaction', [['N', 'None'], ['R', 'Required']]], S: ['Scope', [['U', 'Unchanged'], ['C', 'Changed']]],
  C: ['Confidentiality', HLN], I: ['Integrity', HLN], A: ['Availability', HLN],
  E: ['Exploit Code Maturity', [X, ['H', 'High'], ['F', 'Functional'], ['P', 'Proof-of-Concept'], ['U', 'Unproven']]],
  RL: ['Remediation Level', [X, ['U', 'Unavailable'], ['W', 'Workaround'], ['T', 'Temporary Fix'], ['O', 'Official Fix']]],
  RC: ['Report Confidence', [X, ['C', 'Confirmed'], ['R', 'Reasonable'], ['U', 'Unknown']]],
  CR: ['Confidentiality Requirement', REQ], IR: ['Integrity Requirement', REQ], AR: ['Availability Requirement', REQ],
  MAV: ['Attack Vector', [X, ...AV3]], MAC: ['Attack Complexity', [X, ['L', 'Low'], ['H', 'High']]], MPR: ['Privileges Required', [X, ['N', 'None'], ['L', 'Low'], ['H', 'High']]],
  MUI: ['User Interaction', [X, ['N', 'None'], ['R', 'Required']]], MS: ['Scope', [X, ['U', 'Unchanged'], ['C', 'Changed']]],
  MC: ['Confidentiality', [X, ...HLN]], MI: ['Integrity', [X, ...HLN]], MA: ['Availability', [X, ...HLN]],
};

/* Translations of every English phrase above (a unit test checks coverage). */
export const T = {
  it: {
    'Base Metrics': 'Metriche di base', 'Exploitability Metrics': 'Sfruttabilità', 'Vulnerable System Impact Metrics': 'Impatto sul sistema vulnerabile', 'Subsequent System Impact Metrics': 'Impatto sui sistemi successivi',
    'Threat Metrics': 'Metriche di minaccia', 'Environmental (Security Requirements)': 'Ambientali (requisiti di sicurezza)', 'Environmental (Modified Base Metrics)': 'Ambientali (metriche di base modificate)', 'Supplemental Metrics': 'Metriche supplementari',
    'Temporal Metrics': 'Metriche temporali', 'Impact Metrics': 'Impatto', Scope: 'Ambito',
    'Attack Vector': 'Vettore di attacco', 'Attack Complexity': 'Complessità dell\'attacco', 'Attack Requirements': 'Requisiti dell\'attacco', 'Privileges Required': 'Privilegi richiesti', 'User Interaction': 'Interazione dell\'utente',
    Confidentiality: 'Riservatezza', Integrity: 'Integrità', Availability: 'Disponibilità', 'Exploit Maturity': 'Maturità dell\'exploit',
    'Confidentiality Requirements': 'Requisito di riservatezza', 'Integrity Requirements': 'Requisito di integrità', 'Availability Requirements': 'Requisito di disponibilità',
    'Confidentiality Requirement': 'Requisito di riservatezza', 'Integrity Requirement': 'Requisito di integrità', 'Availability Requirement': 'Requisito di disponibilità',
    Safety: 'Sicurezza delle persone', Automatable: 'Automatizzabile', Recovery: 'Ripristino', 'Value Density': 'Densità del valore', 'Vulnerability Response Effort': 'Sforzo di risposta', 'Provider Urgency': 'Urgenza del fornitore',
    'Exploit Code Maturity': 'Maturità del codice di exploit', 'Remediation Level': 'Livello di rimedio', 'Report Confidence': 'Affidabilità della segnalazione',
    'Not Defined': 'Non definito', Network: 'Rete', Adjacent: 'Adiacente', 'Adjacent Network': 'Rete adiacente', Local: 'Locale', Physical: 'Fisico', Low: 'Basso', High: 'Alto', None: 'Nessuno', Medium: 'Medio',
    Present: 'Presente', Passive: 'Passiva', Active: 'Attiva', Negligible: 'Trascurabile', Attacked: 'Attaccato', POC: 'PoC', Unreported: 'Non segnalato',
    No: 'No', Yes: 'Sì', Automatic: 'Automatico', User: 'Utente', Irrecoverable: 'Irrecuperabile', Diffuse: 'Diffusa', Concentrated: 'Concentrata', Moderate: 'Moderato',
    Clear: 'Clear', Green: 'Green', Amber: 'Amber', Red: 'Red', Required: 'Richiesta', Unchanged: 'Invariato', Changed: 'Modificato',
    Functional: 'Funzionante', 'Proof-of-Concept': 'Proof of concept', Unproven: 'Non dimostrato', Unavailable: 'Non disponibile', Workaround: 'Soluzione alternativa', 'Temporary Fix': 'Correzione temporanea', 'Official Fix': 'Correzione ufficiale',
    Confirmed: 'Confermata', Reasonable: 'Ragionevole', Unknown: 'Sconosciuta',
  },
  es: {
    'Base Metrics': 'Métricas base', 'Exploitability Metrics': 'Explotabilidad', 'Vulnerable System Impact Metrics': 'Impacto en el sistema vulnerable', 'Subsequent System Impact Metrics': 'Impacto en sistemas posteriores',
    'Threat Metrics': 'Métricas de amenaza', 'Environmental (Security Requirements)': 'Entorno (requisitos de seguridad)', 'Environmental (Modified Base Metrics)': 'Entorno (métricas base modificadas)', 'Supplemental Metrics': 'Métricas suplementarias',
    'Temporal Metrics': 'Métricas temporales', 'Impact Metrics': 'Impacto', Scope: 'Alcance',
    'Attack Vector': 'Vector de ataque', 'Attack Complexity': 'Complejidad del ataque', 'Attack Requirements': 'Requisitos del ataque', 'Privileges Required': 'Privilegios requeridos', 'User Interaction': 'Interacción del usuario',
    Confidentiality: 'Confidencialidad', Integrity: 'Integridad', Availability: 'Disponibilidad', 'Exploit Maturity': 'Madurez del exploit',
    'Confidentiality Requirements': 'Requisito de confidencialidad', 'Integrity Requirements': 'Requisito de integridad', 'Availability Requirements': 'Requisito de disponibilidad',
    'Confidentiality Requirement': 'Requisito de confidencialidad', 'Integrity Requirement': 'Requisito de integridad', 'Availability Requirement': 'Requisito de disponibilidad',
    Safety: 'Seguridad física', Automatable: 'Automatizable', Recovery: 'Recuperación', 'Value Density': 'Densidad de valor', 'Vulnerability Response Effort': 'Esfuerzo de respuesta', 'Provider Urgency': 'Urgencia del proveedor',
    'Exploit Code Maturity': 'Madurez del código de exploit', 'Remediation Level': 'Nivel de remediación', 'Report Confidence': 'Confianza del informe',
    'Not Defined': 'No definido', Network: 'Red', Adjacent: 'Adyacente', 'Adjacent Network': 'Red adyacente', Local: 'Local', Physical: 'Físico', Low: 'Bajo', High: 'Alto', None: 'Ninguno', Medium: 'Medio',
    Present: 'Presente', Passive: 'Pasiva', Active: 'Activa', Negligible: 'Insignificante', Attacked: 'Atacado', POC: 'PoC', Unreported: 'No informado',
    No: 'No', Yes: 'Sí', Automatic: 'Automática', User: 'Usuario', Irrecoverable: 'Irrecuperable', Diffuse: 'Difusa', Concentrated: 'Concentrada', Moderate: 'Moderado',
    Clear: 'Clear', Green: 'Green', Amber: 'Amber', Red: 'Red', Required: 'Requerida', Unchanged: 'Sin cambios', Changed: 'Cambiado',
    Functional: 'Funcional', 'Proof-of-Concept': 'Prueba de concepto', Unproven: 'No probado', Unavailable: 'No disponible', Workaround: 'Solución alternativa', 'Temporary Fix': 'Corrección temporal', 'Official Fix': 'Corrección oficial',
    Confirmed: 'Confirmada', Reasonable: 'Razonable', Unknown: 'Desconocida',
  },
  de: {
    'Base Metrics': 'Basismetriken', 'Exploitability Metrics': 'Ausnutzbarkeit', 'Vulnerable System Impact Metrics': 'Auswirkung auf das verwundbare System', 'Subsequent System Impact Metrics': 'Auswirkung auf nachgelagerte Systeme',
    'Threat Metrics': 'Bedrohungsmetriken', 'Environmental (Security Requirements)': 'Umgebung (Sicherheitsanforderungen)', 'Environmental (Modified Base Metrics)': 'Umgebung (modifizierte Basismetriken)', 'Supplemental Metrics': 'Ergänzende Metriken',
    'Temporal Metrics': 'Zeitliche Metriken', 'Impact Metrics': 'Auswirkung', Scope: 'Geltungsbereich',
    'Attack Vector': 'Angriffsvektor', 'Attack Complexity': 'Angriffskomplexität', 'Attack Requirements': 'Angriffsvoraussetzungen', 'Privileges Required': 'Erforderliche Rechte', 'User Interaction': 'Benutzerinteraktion',
    Confidentiality: 'Vertraulichkeit', Integrity: 'Integrität', Availability: 'Verfügbarkeit', 'Exploit Maturity': 'Exploit-Reife',
    'Confidentiality Requirements': 'Vertraulichkeitsanforderung', 'Integrity Requirements': 'Integritätsanforderung', 'Availability Requirements': 'Verfügbarkeitsanforderung',
    'Confidentiality Requirement': 'Vertraulichkeitsanforderung', 'Integrity Requirement': 'Integritätsanforderung', 'Availability Requirement': 'Verfügbarkeitsanforderung',
    Safety: 'Sicherheit (Safety)', Automatable: 'Automatisierbar', Recovery: 'Wiederherstellung', 'Value Density': 'Wertdichte', 'Vulnerability Response Effort': 'Reaktionsaufwand', 'Provider Urgency': 'Dringlichkeit laut Anbieter',
    'Exploit Code Maturity': 'Reife des Exploit-Codes', 'Remediation Level': 'Behebungsstand', 'Report Confidence': 'Vertrauen in die Meldung',
    'Not Defined': 'Nicht definiert', Network: 'Netzwerk', Adjacent: 'Benachbart', 'Adjacent Network': 'Benachbartes Netzwerk', Local: 'Lokal', Physical: 'Physisch', Low: 'Niedrig', High: 'Hoch', None: 'Keine', Medium: 'Mittel',
    Present: 'Vorhanden', Passive: 'Passiv', Active: 'Aktiv', Negligible: 'Vernachlässigbar', Attacked: 'Angegriffen', POC: 'PoC', Unreported: 'Nicht gemeldet',
    No: 'Nein', Yes: 'Ja', Automatic: 'Automatisch', User: 'Benutzer', Irrecoverable: 'Nicht wiederherstellbar', Diffuse: 'Diffus', Concentrated: 'Konzentriert', Moderate: 'Mäßig',
    Clear: 'Clear', Green: 'Green', Amber: 'Amber', Red: 'Red', Required: 'Erforderlich', Unchanged: 'Unverändert', Changed: 'Verändert',
    Functional: 'Funktionsfähig', 'Proof-of-Concept': 'Proof of Concept', Unproven: 'Unbewiesen', Unavailable: 'Nicht verfügbar', Workaround: 'Workaround', 'Temporary Fix': 'Vorläufige Korrektur', 'Official Fix': 'Offizielle Korrektur',
    Confirmed: 'Bestätigt', Reasonable: 'Plausibel', Unknown: 'Unbekannt',
  },
  fr: {
    'Base Metrics': 'Métriques de base', 'Exploitability Metrics': 'Exploitabilité', 'Vulnerable System Impact Metrics': 'Impact sur le système vulnérable', 'Subsequent System Impact Metrics': 'Impact sur les systèmes suivants',
    'Threat Metrics': 'Métriques de menace', 'Environmental (Security Requirements)': 'Environnement (exigences de sécurité)', 'Environmental (Modified Base Metrics)': 'Environnement (métriques de base modifiées)', 'Supplemental Metrics': 'Métriques supplémentaires',
    'Temporal Metrics': 'Métriques temporelles', 'Impact Metrics': 'Impact', Scope: 'Portée',
    'Attack Vector': 'Vecteur d\'attaque', 'Attack Complexity': 'Complexité de l\'attaque', 'Attack Requirements': 'Prérequis de l\'attaque', 'Privileges Required': 'Privilèges requis', 'User Interaction': 'Interaction utilisateur',
    Confidentiality: 'Confidentialité', Integrity: 'Intégrité', Availability: 'Disponibilité', 'Exploit Maturity': 'Maturité de l\'exploit',
    'Confidentiality Requirements': 'Exigence de confidentialité', 'Integrity Requirements': 'Exigence d\'intégrité', 'Availability Requirements': 'Exigence de disponibilité',
    'Confidentiality Requirement': 'Exigence de confidentialité', 'Integrity Requirement': 'Exigence d\'intégrité', 'Availability Requirement': 'Exigence de disponibilité',
    Safety: 'Sécurité des personnes', Automatable: 'Automatisable', Recovery: 'Rétablissement', 'Value Density': 'Densité de valeur', 'Vulnerability Response Effort': 'Effort de réponse', 'Provider Urgency': 'Urgence selon le fournisseur',
    'Exploit Code Maturity': 'Maturité du code d\'exploit', 'Remediation Level': 'Niveau de correction', 'Report Confidence': 'Fiabilité du signalement',
    'Not Defined': 'Non défini', Network: 'Réseau', Adjacent: 'Adjacent', 'Adjacent Network': 'Réseau adjacent', Local: 'Local', Physical: 'Physique', Low: 'Faible', High: 'Élevé', None: 'Aucun', Medium: 'Moyen',
    Present: 'Présent', Passive: 'Passive', Active: 'Active', Negligible: 'Négligeable', Attacked: 'Attaqué', POC: 'PoC', Unreported: 'Non signalé',
    No: 'Non', Yes: 'Oui', Automatic: 'Automatique', User: 'Utilisateur', Irrecoverable: 'Irrécupérable', Diffuse: 'Diffuse', Concentrated: 'Concentrée', Moderate: 'Modéré',
    Clear: 'Clear', Green: 'Green', Amber: 'Amber', Red: 'Red', Required: 'Requise', Unchanged: 'Inchangée', Changed: 'Modifiée',
    Functional: 'Fonctionnel', 'Proof-of-Concept': 'Preuve de concept', Unproven: 'Non prouvé', Unavailable: 'Indisponible', Workaround: 'Contournement', 'Temporary Fix': 'Correctif temporaire', 'Official Fix': 'Correctif officiel',
    Confirmed: 'Confirmé', Reasonable: 'Raisonnable', Unknown: 'Inconnu',
  },
  pt: {
    'Base Metrics': 'Métricas base', 'Exploitability Metrics': 'Explorabilidade', 'Vulnerable System Impact Metrics': 'Impacto no sistema vulnerável', 'Subsequent System Impact Metrics': 'Impacto em sistemas subsequentes',
    'Threat Metrics': 'Métricas de ameaça', 'Environmental (Security Requirements)': 'Ambiente (requisitos de segurança)', 'Environmental (Modified Base Metrics)': 'Ambiente (métricas base modificadas)', 'Supplemental Metrics': 'Métricas suplementares',
    'Temporal Metrics': 'Métricas temporais', 'Impact Metrics': 'Impacto', Scope: 'Escopo',
    'Attack Vector': 'Vetor de ataque', 'Attack Complexity': 'Complexidade do ataque', 'Attack Requirements': 'Requisitos do ataque', 'Privileges Required': 'Privilégios necessários', 'User Interaction': 'Interação do usuário',
    Confidentiality: 'Confidencialidade', Integrity: 'Integridade', Availability: 'Disponibilidade', 'Exploit Maturity': 'Maturidade do exploit',
    'Confidentiality Requirements': 'Requisito de confidencialidade', 'Integrity Requirements': 'Requisito de integridade', 'Availability Requirements': 'Requisito de disponibilidade',
    'Confidentiality Requirement': 'Requisito de confidencialidade', 'Integrity Requirement': 'Requisito de integridade', 'Availability Requirement': 'Requisito de disponibilidade',
    Safety: 'Segurança física', Automatable: 'Automatizável', Recovery: 'Recuperação', 'Value Density': 'Densidade de valor', 'Vulnerability Response Effort': 'Esforço de resposta', 'Provider Urgency': 'Urgência do fornecedor',
    'Exploit Code Maturity': 'Maturidade do código de exploit', 'Remediation Level': 'Nível de correção', 'Report Confidence': 'Confiança do relato',
    'Not Defined': 'Não definido', Network: 'Rede', Adjacent: 'Adjacente', 'Adjacent Network': 'Rede adjacente', Local: 'Local', Physical: 'Físico', Low: 'Baixo', High: 'Alto', None: 'Nenhum', Medium: 'Médio',
    Present: 'Presente', Passive: 'Passiva', Active: 'Ativa', Negligible: 'Desprezível', Attacked: 'Atacado', POC: 'PoC', Unreported: 'Não relatado',
    No: 'Não', Yes: 'Sim', Automatic: 'Automática', User: 'Usuário', Irrecoverable: 'Irrecuperável', Diffuse: 'Difusa', Concentrated: 'Concentrada', Moderate: 'Moderado',
    Clear: 'Clear', Green: 'Green', Amber: 'Amber', Red: 'Red', Required: 'Necessária', Unchanged: 'Inalterado', Changed: 'Alterado',
    Functional: 'Funcional', 'Proof-of-Concept': 'Prova de conceito', Unproven: 'Não comprovado', Unavailable: 'Indisponível', Workaround: 'Solução alternativa', 'Temporary Fix': 'Correção temporária', 'Official Fix': 'Correção oficial',
    Confirmed: 'Confirmado', Reasonable: 'Razoável', Unknown: 'Desconhecido',
  },
};

/** Every English phrase used by the definitions (for the coverage test). */
export function phrases() {
  const s = new Set();
  for (const g of [...V4_GROUPS, ...V31_GROUPS]) { s.add(g.name); for (const [n] of g.sub) if (n) s.add(n); }
  for (const [name, vals] of [...Object.values(V4_METRICS), ...Object.values(V31_METRICS)]) { s.add(name); for (const [, v] of vals) s.add(v); }
  return [...s];
}
