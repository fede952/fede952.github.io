---
title: "CISA Alerta sobre Backdoor FIRESTARTER Mirando Dispositivos Cisco Firepower"
date: "2026-04-23T12:00:00"
lang: "pt"
translationKey: "cisa-warns-of-firestarter-backdoor-targeting-cisco-firepower-devices"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA e NCSC alertam sobre atores APT usando backdoor FIRESTARTER para persistência em dispositivos Cisco ASA/FTD. Ações de resposta urgentes são descritas."
original_url: "https://www.cisa.gov/news-events/analysis-reports/ar26-113a"
source: "CISA"
severity: "High"
target: "Dispositivos Cisco Firepower e Secure Firewall"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA e NCSC alertam sobre atores APT usando backdoor FIRESTARTER para persistência em dispositivos Cisco ASA/FTD. Ações de resposta urgentes são descritas.

{{< cyber-report severity="High" source="CISA" target="Dispositivos Cisco Firepower e Secure Firewall" >}}

A CISA e o NCSC do Reino Unido publicaram um Relatório de Análise de Malware sobre o backdoor FIRESTARTER, que está sendo usado por atores de ameaça persistente avançada (APT) para manter persistência em dispositivos Cisco Firepower e Secure Firewall acessíveis publicamente que executam software ASA ou FTD. A análise é baseada em uma amostra obtida de uma investigação forense, e a CISA confirmou implantações bem-sucedidas no mundo real em dispositivos Cisco Firepower com software ASA.

{{< ad-banner >}}

A divulgação está alinhada com a Diretiva de Emergência 25-03 da CISA, instando as agências FCEB dos EUA a coletar e enviar core dumps para a plataforma Malware Next Generation da CISA e relatar imediatamente os envios através do Centro de Operações 24/7. As organizações são aconselhadas a não tomar nenhuma ação adicional até que a CISA forneça os próximos passos.

Embora o malware seja relevante tanto para dispositivos Cisco Firepower quanto para Secure Firewall, a CISA observou implantações bem-sucedidas apenas em dispositivos Firepower executando ASA. O relatório enfatiza a necessidade de vigilância e busca proativa por indicadores de comprometimento.

{{< netrunner-insight >}}

Analistas de SOC devem priorizar a coleta de core dumps de dispositivos Cisco ASA/FTD e enviá-los à CISA para análise. Equipes DevSecOps devem garantir que os dispositivos Cisco estejam corrigidos e configurados de acordo com as melhores práticas, e monitorar mecanismos de persistência incomuns. Este backdoor destaca a criticidade de proteger dispositivos de borda de rede contra ameaças de nível APT.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/analysis-reports/ar26-113a)**
