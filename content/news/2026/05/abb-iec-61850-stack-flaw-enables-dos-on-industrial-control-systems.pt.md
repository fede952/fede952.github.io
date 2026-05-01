---
title: "Falha na Pilha IEC 61850 da ABB Permite DoS em Sistemas de Controle Industrial"
date: "2026-05-01T09:03:14Z"
original_date: "2026-04-30T12:00:00"
lang: "pt"
translationKey: "abb-iec-61850-stack-flaw-enables-dos-on-industrial-control-systems"
author: "NewsBot (Validated by Federico Sella)"
description: "A CISA alerta sobre uma vulnerabilidade reportada de forma privada na implementação do IEC 61850 MMS da ABB, afetando os produtos System 800xA e Symphony Plus, levando a falhas de dispositivo e negação de serviço."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-01"
source: "CISA"
severity: "High"
target: "ABB System 800xA, Symphony Plus IEC 61850"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

A CISA alerta sobre uma vulnerabilidade reportada de forma privada na implementação do IEC 61850 MMS da ABB, afetando os produtos System 800xA e Symphony Plus, levando a falhas de dispositivo e negação de serviço.

{{< cyber-report severity="High" source="CISA" target="ABB System 800xA, Symphony Plus IEC 61850" >}}

A CISA emitiu um aviso (ICSA-26-120-01) sobre uma vulnerabilidade na implementação da pilha de comunicação IEC 61850 para aplicações cliente MMS da ABB. A falha afeta vários produtos das linhas System 800xA e Symphony Plus, incluindo AC800M CI868, Symphony Plus SD Series CI850, PM 877 e S+ Operations. A exploração requer acesso prévio à rede IEC 61850 do local.

{{< ad-banner >}}

A exploração bem-sucedida causa uma falha de dispositivo nos módulos PM 877, CI850 e CI868, exigindo uma reinicialização manual. Para nós S+ Operations, o ataque trava o driver de comunicação IEC 61850, levando a uma condição de negação de serviço se repetido. No entanto, a disponibilidade e funcionalidade geral do nó permanecem inalteradas, e a comunicação do protocolo GOOSE não é afetada. O System 800xA IEC61850 Connect também não é vulnerável.

As versões de firmware afetadas abrangem vários ramos, incluindo S+ Operations até 6.2.0006.0 e várias versões do PM 877. Nenhum identificador CVE ou pontuação CVSS foi fornecido no aviso. As organizações que usam esses produtos devem revisar o aviso e aplicar mitigações, como segmentação de rede e controles de acesso, para limitar a exposição à rede IEC 61850.

{{< netrunner-insight >}}

Esta vulnerabilidade ressalta a importância da segmentação de rede em ambientes de TI operacional (OT). Como a exploração requer acesso à rede IEC 61850, isolar essa rede da TI corporativa e da internet é crítico. Analistas de SOC devem monitorar tráfego IEC 61850 anômalo, enquanto engenheiros DevSecOps devem priorizar a aplicação de patches e considerar a implementação de detecção de intrusão para anomalias no protocolo MMS.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-01)**
