---
title: "La botnet NadMesh ataca servicios de IA expuestos para robar credenciales en la nube"
date: "2026-07-19T09:05:56Z"
original_date: "2026-07-17T17:12:23"
lang: "es"
translationKey: "nadmesh-botnet-targets-exposed-ai-services-for-cloud-credentials"
slug: "nadmesh-botnet-targets-exposed-ai-services-for-cloud-credentials"
author: "NewsBot (Validated by Federico Sella)"
description: "Una nueva botnet basada en Go, NadMesh, busca plataformas de IA expuestas como ComfyUI y Ollama, robando claves de AWS y tokens de Kubernetes. Se afirma que se han robado más de 3.800 claves."
original_url: "https://thehackernews.com/2026/07/new-nadmesh-botnet-hunts-exposed-ai.html"
source: "The Hacker News"
severity: "High"
target: "Servicios de IA expuestos (ComfyUI, Ollama, n8n, etc.)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Una nueva botnet basada en Go, NadMesh, busca plataformas de IA expuestas como ComfyUI y Ollama, robando claves de AWS y tokens de Kubernetes. Se afirma que se han robado más de 3.800 claves.

{{< cyber-report severity="High" source="The Hacker News" target="Servicios de IA expuestos (ComfyUI, Ollama, n8n, etc.)" >}}

Una nueva botnet llamada NadMesh, escrita en Go, surgió a principios de julio de 2026, dirigida a servicios de IA expuestos para robar credenciales en la nube y tokens de Kubernetes. El panel de control del operador de la botnet muestra supuestamente 3.811 claves únicas de AWS recolectadas, lo que indica una escala operativa significativa. NadMesh utiliza un recolector basado en Shodan para llenar continuamente su cola de escaneo con instancias vulnerables de herramientas populares de IA como ComfyUI, Ollama, n8n, Open WebUI, Langflow y Gradio.

{{< ad-banner >}}

Estas plataformas de IA suelen ser desplegadas rápidamente por equipos de desarrollo sin la seguridad adecuada, quedando expuestas a internet. La botnet explota esta falta de protección de firewall para acceder y extraer credenciales sensibles. El enfoque en servicios de IA sugiere un cambio en los objetivos de los atacantes hacia infraestructura en la nube de alto valor y pipelines de aprendizaje automático.

Las organizaciones que ejecutan estas herramientas de IA deberían auditar inmediatamente su exposición, restringir el acceso a la red y rotar cualquier credencial que pueda haber sido comprometida. La botnet NadMesh demuestra el creciente panorama de amenazas donde los servicios de IA mal configurados se convierten en objetivos principales para el robo de credenciales y el movimiento lateral.

{{< netrunner-insight >}}

Para los analistas del SOC: priorice el escaneo de servicios expuestos de ComfyUI, Ollama y similares en su entorno. Los equipos de DevSecOps deben imponer segmentación de red y reglas de firewall antes de desplegar estas herramientas. La botnet NadMesh es un claro recordatorio de que el despliegue rápido sin revisión de seguridad invita a la recolección automatizada de credenciales.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/07/new-nadmesh-botnet-hunts-exposed-ai.html)**
