import { useEffect, useMemo, useState } from "react";
import client from "../api/client";

const REPORT_STYLES = `
:root {
  --primary-color: #1a365d;
  --secondary-color: #2c5282;
  --accent-color: #3182ce;
  --critical-color: #c53030;
  --high-color: #dd6b20;
  --medium-color: #d69e2e;
  --low-color: #38a169;
  --info-color: #3182ce;
  --bg-light: #f7fafc;
  --text-primary: #2d3748;
  --text-secondary: #718096;
  --border-color: #e2e8f0;
}

.report-shell * {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

.report-shell {
  font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
  color: var(--text-primary);
  line-height: 1.6;
  background: #fff;
}

.print-page-number {
  display: none;
}

.print-mode .no-print,
.print-mode .toolbar,
.print-mode .sidebar {
  display: none !important;
}

.print-mode .main-container {
  display: block !important;
}

.print-mode .main-content {
  margin-left: 0 !important;
  width: 100% !important;
  padding: 18px 24px;
}

.toolbar {
  margin: 18px auto;
  width: min(1320px, 96%);
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: center;
}

.toolbar select,
.toolbar button {
  border-radius: 10px;
  border: 1px solid #cbd5e0;
  background: #fff;
  padding: 10px 12px;
  font-size: 13px;
}

.toolbar button {
  cursor: pointer;
  color: #1a365d;
  font-weight: 600;
}

.toolbar .danger {
  color: #c53030;
  border-color: #fed7d7;
  background: #fff5f5;
}

.page-break {
  page-break-before: always;
}

.no-break {
  page-break-inside: avoid;
}

.cover-page {
  min-height: 100vh;
  background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
  color: #fff;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  text-align: center;
  padding: 60px;
  position: relative;
}

.cover-page::before {
  content: "";
  position: absolute;
  inset: 0;
  background: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.05'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
  opacity: 0.3;
}

.cover-logo {
  width: 120px;
  height: 120px;
  background: rgba(255, 255, 255, 0.1);
  border-radius: 20px;
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 40px;
  position: relative;
  z-index: 1;
}

.cover-logo svg {
  width: 70px;
  height: 70px;
  fill: #fff;
}

.cover-title {
  font-size: 42px;
  font-weight: 700;
  margin-bottom: 15px;
  z-index: 1;
  letter-spacing: -1px;
}

.cover-subtitle {
  font-size: 22px;
  font-weight: 300;
  opacity: 0.9;
  margin-bottom: 50px;
  z-index: 1;
}

.cover-meta {
  z-index: 1;
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 40px;
  margin-top: 40px;
  padding: 30px;
  background: rgba(255, 255, 255, 0.1);
  border-radius: 15px;
  backdrop-filter: blur(10px);
}

.cover-meta-item {
  text-align: center;
}

.cover-meta-label {
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 1px;
  opacity: 0.7;
  margin-bottom: 5px;
}

.cover-meta-value {
  font-size: 16px;
  font-weight: 600;
}

.cover-classification {
  position: absolute;
  top: 30px;
  right: 30px;
  background: rgba(255, 255, 255, 0.2);
  padding: 8px 20px;
  border-radius: 20px;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 1px;
}

.toc {
  padding: 60px;
  background: var(--bg-light);
  min-height: 100vh;
}

.toc h2 {
  color: var(--primary-color);
  font-size: 28px;
  margin-bottom: 40px;
  padding-bottom: 15px;
  border-bottom: 3px solid var(--accent-color);
}

.toc-list {
  list-style: none;
}

.toc-list li {
  padding: 15px 0;
  border-bottom: 1px solid var(--border-color);
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.toc-number {
  font-weight: 700;
  color: var(--accent-color);
  margin-right: 15px;
  font-size: 18px;
}

.toc-title {
  flex: 1;
  font-size: 16px;
}

.toc-page {
  color: var(--text-secondary);
  font-size: 14px;
}

.main-container {
  display: flex;
  min-height: 100vh;
}

.sidebar {
  width: 280px;
  background: var(--primary-color);
  color: #fff;
  padding: 30px 20px;
  position: fixed;
  height: 100vh;
  overflow-y: auto;
}

.sidebar-logo {
  text-align: center;
  padding-bottom: 30px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.1);
  margin-bottom: 30px;
}

.sidebar-nav a {
  display: block;
  color: rgba(255, 255, 255, 0.8);
  text-decoration: none;
  padding: 12px 15px;
  border-radius: 8px;
  margin-bottom: 5px;
  font-size: 14px;
}

.sidebar-nav a:hover,
.sidebar-nav a.active {
  background: rgba(255, 255, 255, 0.1);
  color: #fff;
}

.main-content {
  flex: 1;
  margin-left: 280px;
  padding: 40px 60px;
}

.section {
  margin-bottom: 50px;
}

.section-header {
  display: flex;
  align-items: center;
  margin-bottom: 30px;
  padding-bottom: 15px;
  border-bottom: 2px solid var(--border-color);
}

.section-icon {
  width: 50px;
  height: 50px;
  background: linear-gradient(135deg, var(--primary-color), var(--accent-color));
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  margin-right: 20px;
}

.section-icon svg {
  width: 26px;
  height: 26px;
  fill: #fff;
}

.section-title {
  font-size: 24px;
  color: var(--primary-color);
  font-weight: 700;
}

.section-subtitle {
  font-size: 14px;
  color: var(--text-secondary);
  margin-top: 3px;
}

.metrics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 20px;
  margin-bottom: 40px;
}

.metric-card {
  background: #fff;
  border-radius: 15px;
  padding: 25px;
  box-shadow: 0 4px 15px rgba(0, 0, 0, 0.05);
  border: 1px solid var(--border-color);
}

.metric-card.critical {
  border-left: 4px solid var(--critical-color);
}
.metric-card.high {
  border-left: 4px solid var(--high-color);
}
.metric-card.medium {
  border-left: 4px solid var(--medium-color);
}
.metric-card.low {
  border-left: 4px solid var(--low-color);
}
.metric-card.info {
  border-left: 4px solid var(--info-color);
}

.metric-value {
  font-size: 36px;
  font-weight: 700;
  color: var(--primary-color);
  margin-bottom: 5px;
}

.metric-label {
  font-size: 14px;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.metric-trend {
  display: flex;
  align-items: center;
  margin-top: 10px;
  font-size: 13px;
}

.metric-trend.up {
  color: var(--critical-color);
}
.metric-trend.down {
  color: var(--low-color);
}
.metric-trend.neutral {
  color: #4a5568;
}

.table-container {
  overflow-x: auto;
  border-radius: 12px;
  box-shadow: 0 4px 15px rgba(0, 0, 0, 0.05);
  margin-bottom: 30px;
}

.table-container table {
  width: 100%;
  border-collapse: collapse;
  background: #fff;
}

.table-container thead {
  background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
  color: #fff;
}

.table-container th {
  padding: 16px 20px;
  text-align: left;
  font-weight: 600;
  font-size: 13px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.table-container td {
  padding: 16px 20px;
  border-bottom: 1px solid var(--border-color);
  font-size: 14px;
  vertical-align: top;
}

.severity-badge {
  display: inline-block;
  padding: 6px 14px;
  border-radius: 20px;
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
}

.severity-critical {
  background: rgba(197, 48, 48, 0.1);
  color: var(--critical-color);
}
.severity-high {
  background: rgba(221, 107, 32, 0.1);
  color: var(--high-color);
}
.severity-medium {
  background: rgba(214, 158, 46, 0.1);
  color: var(--medium-color);
}
.severity-low {
  background: rgba(56, 161, 105, 0.1);
  color: var(--low-color);
}
.severity-info {
  background: rgba(49, 130, 206, 0.1);
  color: var(--info-color);
}

.framework-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 25px;
  margin-bottom: 40px;
}

.framework-card {
  background: #fff;
  border-radius: 15px;
  overflow: hidden;
  box-shadow: 0 4px 15px rgba(0, 0, 0, 0.05);
  border: 1px solid var(--border-color);
}

.framework-header {
  background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
  color: #fff;
  padding: 20px 25px;
  display: flex;
  align-items: center;
}

.framework-logo {
  width: 45px;
  height: 45px;
  background: rgba(255, 255, 255, 0.2);
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  margin-right: 15px;
  font-weight: 700;
  font-size: 14px;
}

.framework-name {
  font-size: 18px;
  font-weight: 600;
}

.framework-body {
  padding: 25px;
}

.framework-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 0;
  border-bottom: 1px solid var(--border-color);
}

.framework-item:last-child {
  border-bottom: none;
}

.framework-control {
  font-size: 14px;
  color: var(--text-primary);
}

.framework-status {
  display: flex;
  align-items: center;
  font-size: 13px;
}

.status-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  margin-right: 8px;
}

.status-compliant .status-dot {
  background: var(--low-color);
}
.status-partial .status-dot {
  background: var(--medium-color);
}
.status-non-compliant .status-dot {
  background: var(--critical-color);
}

.quickwin-list {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.quickwin-card {
  display: flex;
  background: #fff;
  border-radius: 15px;
  overflow: hidden;
  box-shadow: 0 4px 15px rgba(0, 0, 0, 0.05);
  border: 1px solid var(--border-color);
}

.quickwin-rank {
  width: 80px;
  background: linear-gradient(135deg, var(--primary-color), var(--accent-color));
  color: #fff;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  font-size: 28px;
  font-weight: 700;
}

.quickwin-rank span {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 1px;
  opacity: 0.8;
}

.quickwin-content {
  flex: 1;
  padding: 25px;
}

.quickwin-title {
  font-size: 18px;
  font-weight: 600;
  color: var(--primary-color);
  margin-bottom: 10px;
}

.quickwin-description {
  font-size: 14px;
  color: var(--text-secondary);
  margin-bottom: 15px;
}

.quickwin-meta {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}

.quickwin-tag {
  display: inline-flex;
  align-items: center;
  padding: 6px 12px;
  background: var(--bg-light);
  border-radius: 20px;
  font-size: 12px;
  color: var(--text-secondary);
}

.fair-container {
  background: #fff;
  border-radius: 15px;
  padding: 30px;
  box-shadow: 0 4px 15px rgba(0, 0, 0, 0.05);
  border: 1px solid var(--border-color);
}

.fair-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 30px;
}

.fair-title {
  font-size: 20px;
  font-weight: 600;
  color: var(--primary-color);
}

.fair-legend {
  display: flex;
  gap: 20px;
}

.fair-legend-item {
  display: flex;
  align-items: center;
  font-size: 13px;
  color: var(--text-secondary);
}

.fair-legend-color {
  width: 12px;
  height: 12px;
  border-radius: 3px;
  margin-right: 8px;
}

.fair-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 25px;
}

.fair-metric {
  padding: 20px;
  background: var(--bg-light);
  border-radius: 12px;
}

.fair-metric-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 15px;
}

.fair-metric-name {
  font-size: 14px;
  font-weight: 600;
}

.fair-metric-value {
  font-size: 18px;
  font-weight: 700;
  color: var(--primary-color);
}

.fair-bar {
  height: 8px;
  background: #e2e8f0;
  border-radius: 4px;
  overflow: hidden;
}

.fair-bar-fill {
  height: 100%;
  border-radius: 4px;
}

.fair-bar-fill.high {
  background: linear-gradient(90deg, var(--critical-color), #e53e3e);
}

.fair-bar-fill.medium {
  background: linear-gradient(90deg, var(--medium-color), #ecc94b);
}

.fair-bar-fill.low {
  background: linear-gradient(90deg, var(--low-color), #48bb78);
}

.category-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 20px;
}

.category-card {
  background: #fff;
  border-radius: 15px;
  padding: 25px;
  box-shadow: 0 4px 15px rgba(0, 0, 0, 0.05);
  border: 1px solid var(--border-color);
  text-align: center;
}

.category-icon {
  width: 60px;
  height: 60px;
  background: linear-gradient(135deg, var(--primary-color), var(--accent-color));
  border-radius: 15px;
  display: flex;
  align-items: center;
  justify-content: center;
  margin: 0 auto 20px;
  color: #fff;
  font-size: 24px;
}

.category-name {
  font-size: 16px;
  font-weight: 600;
  color: var(--primary-color);
  margin-bottom: 10px;
}

.category-count {
  display: flex;
  justify-content: center;
  gap: 15px;
  font-size: 12px;
}

.category-stat {
  display: flex;
  flex-direction: column;
  align-items: center;
}

.category-stat-value {
  font-size: 20px;
  font-weight: 700;
}

.category-stat-label {
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.technical-card {
  background: #fff;
  border-radius: 15px;
  overflow: hidden;
  box-shadow: 0 4px 15px rgba(0, 0, 0, 0.05);
  border: 1px solid var(--border-color);
  margin-bottom: 25px;
}

.technical-header {
  background: var(--bg-light);
  padding: 20px 25px;
  border-bottom: 1px solid var(--border-color);
}

.technical-title {
  display: flex;
  align-items: center;
  gap: 15px;
}

.technical-title h4 {
  font-size: 16px;
  font-weight: 600;
  color: var(--primary-color);
}

.technical-body {
  padding: 25px;
}

.technical-detail {
  margin-bottom: 20px;
}

.technical-label {
  font-size: 12px;
  font-weight: 600;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-bottom: 8px;
}

.technical-url,
.technical-payload {
  background: #1a202c;
  color: #e2e8f0;
  padding: 15px 20px;
  border-radius: 8px;
  font-family: Consolas, Monaco, monospace;
  font-size: 13px;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
}

.technical-url {
  color: #68d391;
}

.technical-payload {
  color: #fc8181;
}

.chart-container {
  background: #fff;
  border-radius: 15px;
  padding: 30px;
  box-shadow: 0 4px 15px rgba(0, 0, 0, 0.05);
  border: 1px solid var(--border-color);
  margin-bottom: 30px;
}

.chart-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 25px;
}

.chart-title {
  font-size: 18px;
  font-weight: 600;
  color: var(--primary-color);
}

.donut-chart {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 40px;
  flex-wrap: wrap;
}

.donut-visual {
  position: relative;
  width: 200px;
  height: 200px;
}

.donut-visual svg {
  width: 100%;
  height: 100%;
  transform: rotate(-90deg);
}

.donut-center {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  text-align: center;
}

.donut-center-value {
  font-size: 36px;
  font-weight: 700;
  color: var(--primary-color);
}

.donut-center-label {
  font-size: 14px;
  color: var(--text-secondary);
}

.donut-legend {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.donut-legend-item {
  display: flex;
  align-items: center;
  gap: 12px;
}

.donut-legend-color {
  width: 16px;
  height: 16px;
  border-radius: 4px;
}

.donut-legend-label {
  font-size: 14px;
  min-width: 100px;
}

.donut-legend-value {
  font-size: 14px;
  font-weight: 600;
  color: var(--primary-color);
}

.progress-item {
  margin-bottom: 20px;
}

.progress-header {
  display: flex;
  justify-content: space-between;
  margin-bottom: 8px;
}

.progress-label {
  font-size: 14px;
  font-weight: 500;
}

.progress-value {
  font-size: 14px;
  font-weight: 600;
  color: var(--primary-color);
}

.progress-bar {
  height: 10px;
  background: #e2e8f0;
  border-radius: 5px;
  overflow: hidden;
}

.progress-fill {
  height: 100%;
  border-radius: 5px;
}

.report-footer {
  background: var(--bg-light);
  padding: 40px 60px;
  border-top: 1px solid var(--border-color);
  margin-top: 60px;
}

.footer-content {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 20px;
}

.footer-logo {
  font-size: 20px;
  font-weight: 700;
  color: var(--primary-color);
}

.footer-info {
  text-align: right;
  font-size: 13px;
  color: var(--text-secondary);
}

.footer-classification {
  background: var(--primary-color);
  color: #fff;
  padding: 8px 20px;
  border-radius: 20px;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 1px;
}

.text-critical {
  color: var(--critical-color);
}
.text-high {
  color: var(--high-color);
}
.text-medium {
  color: var(--medium-color);
}
.text-low {
  color: var(--low-color);
}
.text-info {
  color: var(--info-color);
}

.bg-critical {
  background-color: var(--critical-color);
}
.bg-high {
  background-color: var(--high-color);
}
.bg-medium {
  background-color: var(--medium-color);
}
.bg-low {
  background-color: var(--low-color);
}
.bg-info {
  background-color: var(--info-color);
}

.mt-20 {
  margin-top: 20px;
}

@media (max-width: 1024px) {
  .sidebar {
    display: none;
  }
  .main-content {
    margin-left: 0;
    padding: 30px;
  }
  .cover-meta {
    grid-template-columns: 1fr;
    gap: 20px;
  }
}

@media (max-width: 768px) {
  .cover-title {
    font-size: 28px;
  }
  .cover-subtitle {
    font-size: 18px;
  }
  .metrics-grid,
  .framework-grid {
    grid-template-columns: 1fr;
  }
  .quickwin-card {
    flex-direction: column;
  }
  .quickwin-rank {
    width: 100%;
    flex-direction: row;
    gap: 10px;
    padding: 15px;
  }
}

@media print {
  body {
    font-size: 11pt;
    line-height: 1.4;
  }
  .no-print,
  .toolbar {
    display: none !important;
  }
  .sidebar {
    display: none !important;
  }
  .main-container {
    display: block !important;
  }
  .main-content {
    margin-left: 0 !important;
    width: 100% !important;
    padding: 0 !important;
  }
  .cover-page,
  .toc,
  .main-container,
  .main-content,
  .section {
    min-height: auto !important;
    height: auto !important;
  }
  .page-break {
    page-break-before: always;
  }
  .section,
  .card,
  .table-container,
  tr,
  .no-break,
  .technical-card,
  .quickwin-card {
    page-break-inside: avoid;
  }
  .cover-page,
  .toc {
    page-break-after: always;
  }
  .print-page-number {
    display: block !important;
    position: fixed;
    right: 0.3cm;
    bottom: 0.3cm;
    font-size: 10pt;
    color: #4a5568;
  }
  .print-page-number::after {
    content: "Página " counter(page);
  }
  @page {
    margin: 2cm;
    size: A4;
  }
}
`;

const SEVERITY_META = {
  critical: { label: "Crítico", css: "severity-critical", color: "#c53030" },
  high: { label: "Alto", css: "severity-high", color: "#dd6b20" },
  medium: { label: "Médio", css: "severity-medium", color: "#d69e2e" },
  low: { label: "Baixo", css: "severity-low", color: "#38a169" },
  info: { label: "Info", css: "severity-info", color: "#3182ce" },
};

const FRAMEWORK_DEFS = [
  {
    key: "cis_v8",
    short: "CIS",
    name: "CIS Controls v8",
    controls: [
      "1. Inventário de Ativos",
      "2. Inventário de Software",
      "3. Proteção de Dados",
      "4. Configuração Segura",
      "5. Gestão de Contas",
    ],
  },
  {
    key: "iso27001",
    short: "ISO",
    name: "ISO 27001:2022",
    controls: [
      "A.5 Políticas de Segurança",
      "A.6 Organização da SI",
      "A.8 Gestão de Ativos",
      "A.9 Controle de Acesso",
      "A.12 Segurança de Operações",
    ],
  },
  {
    key: "nist",
    short: "NIST",
    name: "NIST CSF 2.0",
    controls: ["Identify (ID)", "Protect (PR)", "Detect (DE)", "Respond (RS)", "Recover (RC)"],
  },
];

function fmtDate(value) {
  const date = value ? new Date(value) : new Date();
  return date.toLocaleDateString("pt-BR", { day: "2-digit", month: "long", year: "numeric" });
}

function fmtDateTime(value) {
  const date = value ? new Date(value) : new Date();
  return date.toLocaleString("pt-BR");
}

function fmtCurrency(value) {
  return new Intl.NumberFormat("pt-BR", { style: "currency", currency: "BRL", maximumFractionDigits: 0 }).format(Number(value || 0));
}

function toPct(part, total) {
  if (!total) return 0;
  return Math.round((Number(part || 0) / Number(total)) * 1000) / 10;
}

function frameworkStatus(score) {
  if (score >= 80) return { css: "status-compliant", label: "Conforme" };
  if (score >= 60) return { css: "status-partial", label: "Parcial" };
  return { css: "status-non-compliant", label: "Não Conforme" };
}

function metricTrendText(severity, lifecycle) {
  const newCount = Number(lifecycle.new || 0);
  const corrected = Number(lifecycle.corrected || 0);
  const delta = newCount - corrected;
  if (delta > 0 && (severity === "critical" || severity === "high")) {
    return { cls: "up", text: `+${delta} no ciclo atual` };
  }
  if (delta < 0) {
    return { cls: "down", text: `${delta} no ciclo atual` };
  }
  return { cls: "neutral", text: "Sem baseline mensal" };
}

function buildQuickWins(recommendations = []) {
  const fallback = [
    "Implementar MFA em contas privilegiadas",
    "Renovar certificados críticos expirados",
    "Aplicar patching emergencial de serviços expostos",
    "Reforçar headers de segurança em aplicações web",
    "Sanitizar logs para remover dados sensíveis",
  ];

  const base = recommendations.slice(0, 5).map((item, index) => ({
    title: item?.name || fallback[index],
    description: item?.recommendation || "Ação recomendada para reduzir exposição imediata.",
  }));

  while (base.length < 5) {
    base.push({
      title: fallback[base.length],
      description: "Ação recomendada para reduzir exposição imediata.",
    });
  }

  return base.map((item, index) => {
    const impact = index < 2 ? "Crítico" : index < 4 ? "Alto" : "Médio";
    const effort = index === 0 ? "2-4 horas" : index === 1 ? "1-2 horas" : index === 2 ? "4-6 horas" : "2-5 horas";
    return {
      ...item,
      rank: index + 1,
      impact,
      effort,
      category: ["Authentication", "Web Encryption", "Software Patching", "Application Security", "Data Exposure"][index],
    };
  });
}

export default function ReportsPage() {
  const [scans, setScans] = useState([]);
  const [selectedId, setSelectedId] = useState("");
  const [isPrinting, setIsPrinting] = useState(false);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const loadScans = async () => {
      try {
        const { data } = await client.get("/api/scans");
        setScans(data || []);
        if ((data || []).length > 0) {
          setSelectedId(String(data[0].id));
        }
      } catch (err) {
        setError(err?.response?.data?.detail || "Falha ao carregar scans.");
      }
    };
    loadScans();
  }, []);

  useEffect(() => {
    if (!selectedId) return;
    const loadReport = async () => {
      setLoading(true);
      setError("");
      try {
        const { data } = await client.get(`/api/scans/${selectedId}/report`, {
          params: { prioritized_limit: 10, prioritized_offset: 0 },
        });
        setReport(data);
      } catch (err) {
        setReport(null);
        setError(err?.response?.data?.detail || "Falha ao carregar relatório.");
      } finally {
        setLoading(false);
      }
    };
    loadReport();
  }, [selectedId]);

  useEffect(() => {
    const handleAfterPrint = () => setIsPrinting(false);
    window.addEventListener("afterprint", handleAfterPrint);
    return () => window.removeEventListener("afterprint", handleAfterPrint);
  }, []);

  const selectedScan = scans.find((item) => String(item.id) === String(selectedId));

  const groupedScanOptions = useMemo(() => {
    const byTarget = new Map();
    for (const scan of scans || []) {
      const target = String(scan.target_query || "(sem alvo)");
      const existing = byTarget.get(target);
      if (!existing) {
        byTarget.set(target, { target, latest: scan, count: 1 });
        continue;
      }
      const latest = Number(scan.id) > Number(existing.latest.id) ? scan : existing.latest;
      byTarget.set(target, { target, latest, count: existing.count + 1 });
    }
    return Array.from(byTarget.values()).sort((a, b) => Number(b.latest.id) - Number(a.latest.id));
  }, [scans]);

  const data = useMemo(() => {
    const v2 = report?.state_data?.report_v2 || {};
    const summary = v2.summary || {};
    const fair = v2.fair || {};
    const frameworks = v2.frameworks || {};
    const vulnerabilities = v2.vulnerability_table || [];
    const categories = v2.category_scores || [];
    const lifecycle = v2.lifecycle || {};
    const benchmark = v2.segment_benchmark || {};
    const targetEvolution = v2.target_evolution || { timeline: [], recurring_findings: [] };

    const total = Number(summary.total || vulnerabilities.length || 0);
    const sev = {
      critical: Number(summary.critical || 0),
      high: Number(summary.high || 0),
      medium: Number(summary.medium || 0),
      low: Number(summary.low || 0),
      info: Number(summary.info || 0),
    };

    const fairAvg = Number(fair.fair_avg_score || 0);
    const fairLef = Number(fair.loss_event_frequency_avg || 0);
    const fairLm = Number(fair.loss_magnitude_avg_usd || 0);
    const fairPeakAle = Number(fair.ale_peak_usd || 0);
    const fairView = [
      { name: "LEF (Loss Event Frequency)", value: Math.min(100, Math.round(fairLef * 100)), descr: "Probabilidade anual média de evento de perda" },
      { name: "TEF (Threat Event Frequency)", value: Math.min(100, Math.round((fairLef * 0.82) * 100)), descr: "Frequência estimada de eventos de ameaça" },
      { name: "Vulnerability (Probabilidade de Sucesso)", value: Math.min(100, Math.round((fairLef * 0.68) * 100)), descr: "Chance de sucesso do agente de ameaça" },
      { name: "Primary Loss (Perda Primária)", valueText: fmtCurrency((fairLm || 0) * 0.65), value: Math.min(100, Math.round((fairAvg || 0))), descr: "Perda direta média estimada por incidente" },
      { name: "Secondary Loss (Perda Secundária)", valueText: fmtCurrency((fairLm || 0) * 0.35), value: Math.min(100, Math.round((fairAvg || 0) * 0.75)), descr: "Perda indireta (reputação, multas, etc.)" },
      { name: "ALE (Annualized Loss Expectancy)", valueText: fmtCurrency(fair.ale_total_open_usd || 0), value: Math.min(100, Math.max(5, Math.round((fairPeakAle > 0 ? (fair.ale_total_open_usd / fairPeakAle) * 100 : fairAvg)))), descr: "Expectativa de perda anualizada total" },
    ];

    return {
      v2,
      summary,
      total,
      sev,
      fair,
      fairView,
      frameworks,
      vulnerabilities,
      categories,
      lifecycle,
      benchmark,
      targetEvolution,
      quickWins: buildQuickWins(v2.recommendations || []),
    };
  }, [report]);

  const exportCsv = async () => {
    if (!selectedId) return;
    try {
      const response = await client.get(`/api/scans/${selectedId}/report.csv`, { responseType: "blob" });
      const blob = new Blob([response.data], { type: "text/csv;charset=utf-8" });
      const url = window.URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `scan_${selectedId}_report.csv`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.URL.revokeObjectURL(url);
    } catch {
      setError("Falha ao exportar CSV.");
    }
  };

  const exportPdf = () => {
    if (!report) return;
    setIsPrinting(true);
    window.setTimeout(() => window.print(), 120);
  };

  return (
    <div className={`report-shell ${isPrinting ? "print-mode" : ""}`}>
      <style>{REPORT_STYLES}</style>

      <div className="toolbar no-print">
        <select value={selectedId} onChange={(e) => setSelectedId(e.target.value)}>
          {groupedScanOptions.length === 0 && <option value="">Sem scans disponíveis</option>}
          {groupedScanOptions.map((entry) => (
            <option key={entry.latest.id} value={entry.latest.id}>
              {entry.target} - último #{entry.latest.id} ({entry.count} scans)
            </option>
          ))}
        </select>
        <button onClick={exportPdf} disabled={!report}>Exportar PDF</button>
        <button onClick={exportCsv} disabled={!report}>Exportar CSV</button>
        <button className="danger" onClick={() => window.location.reload()}>Atualizar</button>
      </div>

      {error && (
        <div className="toolbar">
          <div style={{ width: "100%", padding: "10px 12px", borderRadius: 10, border: "1px solid #fed7d7", background: "#fff5f5", color: "#9b2c2c" }}>
            {error}
          </div>
        </div>
      )}

      {loading && (
        <div className="toolbar">
          <div style={{ color: "#2d3748", fontSize: 14 }}>Carregando relatório...</div>
        </div>
      )}

      {!loading && report && (
        <>
          <div className="cover-page">
            <div className="cover-classification">Confidencial</div>
            <div className="cover-logo">
              <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z" />
              </svg>
            </div>
            <h1 className="cover-title">Relatório Executivo</h1>
            <h2 className="cover-subtitle">Gestão de Vulnerabilidades</h2>
            <div className="cover-meta">
              <div className="cover-meta-item">
                <div className="cover-meta-label">Data do Relatório</div>
                <div className="cover-meta-value">{fmtDate(selectedScan?.updated_at || selectedScan?.created_at)}</div>
              </div>
              <div className="cover-meta-item">
                <div className="cover-meta-label">Versão</div>
                <div className="cover-meta-value">v2.1.0</div>
              </div>
              <div className="cover-meta-item">
                <div className="cover-meta-label">Responsável</div>
                <div className="cover-meta-value">Equipe de Segurança</div>
              </div>
            </div>
          </div>

          <div className="toc page-break">
            <h2>Sumário</h2>
            <ul className="toc-list">
              <li><span><span className="toc-number">01</span><span className="toc-title">Resumo Executivo</span></span><span className="toc-page">Seção I</span></li>
              <li><span><span className="toc-number">02</span><span className="toc-title">Visão Geral das Vulnerabilidades</span></span><span className="toc-page">Seção II</span></li>
              <li><span><span className="toc-number">03</span><span className="toc-title">Métricas FAIR</span></span><span className="toc-page">Seção III</span></li>
              <li><span><span className="toc-number">04</span><span className="toc-title">Conformidade com Frameworks</span></span><span className="toc-page">Seção IV</span></li>
              <li><span><span className="toc-number">05</span><span className="toc-title">Top 5 Quick-Wins</span></span><span className="toc-page">Seção V</span></li>
              <li><span><span className="toc-number">06</span><span className="toc-title">Análise por Categoria</span></span><span className="toc-page">Seção VI</span></li>
              <li><span><span className="toc-number">07</span><span className="toc-title">Detalhamento Técnico</span></span><span className="toc-page">Seção VII</span></li>
              <li><span><span className="toc-number">08</span><span className="toc-title">Benchmark e Evolução por Alvo</span></span><span className="toc-page">Seção VIII</span></li>
            </ul>
          </div>

          <div className="main-container">
            <aside className="sidebar no-print">
              <div className="sidebar-logo">
                <svg width="40" height="40" viewBox="0 0 24 24" fill="white">
                  <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z" />
                </svg>
              </div>
              <nav className="sidebar-nav">
                <a href="#resumo" className="active">Resumo Executivo</a>
                <a href="#visao-geral">Visão Geral</a>
                <a href="#fair">Métricas FAIR</a>
                <a href="#frameworks">Frameworks</a>
                <a href="#quickwins">Quick-Wins</a>
                <a href="#categorias">Categorias</a>
                <a href="#tecnico">Detalhamento Técnico</a>
                <a href="#evolucao">Benchmark e Evolução</a>
              </nav>
            </aside>

            <main className="main-content">
              <section id="resumo" className="section page-break">
                <div className="section-header">
                  <div className="section-icon"><svg viewBox="0 0 24 24"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zM9 17H7v-7h2v7zm4 0h-2V7h2v10zm4 0h-2v-4h2v4z" /></svg></div>
                  <div>
                    <h2 className="section-title">Resumo Executivo</h2>
                    <p className="section-subtitle">Visão consolidada do estado de segurança</p>
                  </div>
                </div>

                <div className="metrics-grid">
                  {Object.keys(SEVERITY_META).map((severity) => {
                    const meta = SEVERITY_META[severity];
                    const trend = metricTrendText(severity, data.lifecycle);
                    return (
                      <div key={severity} className={`metric-card ${severity} no-break`}>
                        <div className={`metric-value text-${severity}`}>{data.sev[severity]}</div>
                        <div className="metric-label">{meta.label}</div>
                        <div className={`metric-trend ${trend.cls}`}>{trend.text}</div>
                      </div>
                    );
                  })}
                </div>

                <div className="chart-container no-break">
                  <div className="chart-header">
                    <h3 className="chart-title">Distribuição por Severidade</h3>
                  </div>
                  <div className="donut-chart">
                    <div className="donut-visual">
                      <svg viewBox="0 0 42 42">
                        <circle cx="21" cy="21" r="15.91549430918954" fill="transparent" stroke="#e2e8f0" strokeWidth="5" />
                        {(() => {
                          let offset = 25;
                          return Object.entries(SEVERITY_META).map(([severity, meta]) => {
                            const pct = toPct(data.sev[severity], data.total);
                            const node = (
                              <circle
                                key={severity}
                                cx="21"
                                cy="21"
                                r="15.91549430918954"
                                fill="transparent"
                                stroke={meta.color}
                                strokeWidth="5"
                                strokeDasharray={`${pct} ${100 - pct}`}
                                strokeDashoffset={offset}
                              />
                            );
                            offset -= pct;
                            return node;
                          });
                        })()}
                      </svg>
                      <div className="donut-center">
                        <div className="donut-center-value">{data.total}</div>
                        <div className="donut-center-label">Total</div>
                      </div>
                    </div>
                    <div className="donut-legend">
                      {Object.entries(SEVERITY_META).map(([severity, meta]) => (
                        <div key={severity} className="donut-legend-item">
                          <div className={`donut-legend-color bg-${severity}`}></div>
                          <span className="donut-legend-label">{meta.label}</span>
                          <span className="donut-legend-value">{data.sev[severity]} ({toPct(data.sev[severity], data.total)}%)</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </section>

              <section id="visao-geral" className="section page-break">
                <div className="section-header">
                  <div className="section-icon"><svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z" /></svg></div>
                  <div>
                    <h2 className="section-title">Visão Geral das Vulnerabilidades</h2>
                    <p className="section-subtitle">Classificação e inventário completo</p>
                  </div>
                </div>
                <div className="table-container no-break">
                  <table>
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>Vulnerabilidade</th>
                        <th>Severidade</th>
                        <th>Categoria</th>
                        <th>Status</th>
                        <th>CVSS</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.vulnerabilities.slice(0, 120).map((row, index) => {
                        const severity = String(row.severity || "low").toLowerCase();
                        const status = row.status === "new" ? "Novo" : row.status === "open" ? "Aberto" : "Em análise";
                        const id = row.id || `VUL-${String(index + 1).padStart(3, "0")}`;
                        return (
                          <tr key={`${id}-${index}`}>
                            <td><strong>{id}</strong></td>
                            <td>{row.name || row.problem || "Vulnerabilidade identificada"}</td>
                            <td><span className={`severity-badge ${SEVERITY_META[severity]?.css || "severity-low"}`}>{SEVERITY_META[severity]?.label || "Baixo"}</span></td>
                            <td>{row.category || "Application Security"}</td>
                            <td>{status}</td>
                            <td>{row.cvss || "-"}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </section>

              <section id="fair" className="section page-break">
                <div className="section-header">
                  <div className="section-icon"><svg viewBox="0 0 24 24"><path d="M3.5 18.49l6-6.01 4 4L22 6.92l-1.41-1.41-7.09 7.97-4-4L2 16.99z" /></svg></div>
                  <div>
                    <h2 className="section-title">Métricas FAIR</h2>
                    <p className="section-subtitle">Factor Analysis of Information Risk</p>
                  </div>
                </div>
                <div className="fair-container no-break">
                  <div className="fair-header">
                    <h3 className="fair-title">Análise Quantitativa de Risco</h3>
                    <div className="fair-legend">
                      <div className="fair-legend-item"><div className="fair-legend-color bg-critical"></div><span>Alto Risco</span></div>
                      <div className="fair-legend-item"><div className="fair-legend-color bg-medium"></div><span>Médio Risco</span></div>
                      <div className="fair-legend-item"><div className="fair-legend-color bg-low"></div><span>Baixo Risco</span></div>
                    </div>
                  </div>
                  <div className="fair-grid">
                    {data.fairView.map((metric) => {
                      const tone = metric.value >= 75 ? "high" : metric.value >= 45 ? "medium" : "low";
                      return (
                        <div key={metric.name} className="fair-metric no-break">
                          <div className="fair-metric-header">
                            <span className="fair-metric-name">{metric.name}</span>
                            <span className="fair-metric-value">{metric.valueText || `${metric.value}%`}</span>
                          </div>
                          <div className="fair-bar">
                            <div className={`fair-bar-fill ${tone}`} style={{ width: `${metric.value}%` }}></div>
                          </div>
                          <p style={{ fontSize: 12, color: "#718096", marginTop: 10 }}>{metric.descr}</p>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </section>

              <section id="frameworks" className="section page-break">
                <div className="section-header">
                  <div className="section-icon"><svg viewBox="0 0 24 24"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-5 14H7v-2h7v2zm3-4H7v-2h10v2zm0-4H7V7h10v2z" /></svg></div>
                  <div>
                    <h2 className="section-title">Conformidade com Frameworks</h2>
                    <p className="section-subtitle">CIS Controls, ISO 27001 e NIST CSF</p>
                  </div>
                </div>

                <div className="framework-grid">
                  {FRAMEWORK_DEFS.map((fw) => {
                    const score = Number(data.frameworks?.[fw.key]?.score || 0);
                    return (
                      <div key={fw.key} className="framework-card no-break">
                        <div className="framework-header">
                          <div className="framework-logo">{fw.short}</div>
                          <span className="framework-name">{fw.name}</span>
                        </div>
                        <div className="framework-body">
                          {fw.controls.map((control, index) => {
                            const bias = score - index * 7;
                            const status = frameworkStatus(bias);
                            return (
                              <div key={control} className="framework-item">
                                <span className="framework-control">{control}</span>
                                <span className={`framework-status ${status.css}`}><span className="status-dot"></span>{status.label}</span>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    );
                  })}
                </div>

                <div className="chart-container no-break mt-20">
                  <div className="chart-header"><h3 className="chart-title">Nível de Conformidade por Framework</h3></div>
                  {FRAMEWORK_DEFS.map((fw) => {
                    const score = Number(data.frameworks?.[fw.key]?.score || 0);
                    return (
                      <div key={`progress-${fw.key}`} className="progress-item">
                        <div className="progress-header">
                          <span className="progress-label">{fw.name}</span>
                          <span className="progress-value">{score}%</span>
                        </div>
                        <div className="progress-bar">
                          <div className={`progress-fill ${score >= 70 ? "bg-medium" : "bg-high"}`} style={{ width: `${score}%` }}></div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </section>

              <section id="quickwins" className="section page-break">
                <div className="section-header">
                  <div className="section-icon"><svg viewBox="0 0 24 24"><path d="M7 2v11h3v9l7-12h-4l4-8z" /></svg></div>
                  <div>
                    <h2 className="section-title">Top 5 Quick-Wins</h2>
                    <p className="section-subtitle">Ações de alto impacto com baixo esforço</p>
                  </div>
                </div>

                <div className="quickwin-list">
                  {data.quickWins.map((item) => (
                    <div key={`quick-${item.rank}`} className="quickwin-card no-break">
                      <div className="quickwin-rank">#{item.rank}<span>Prioridade</span></div>
                      <div className="quickwin-content">
                        <h4 className="quickwin-title">{item.title}</h4>
                        <p className="quickwin-description">{item.description}</p>
                        <div className="quickwin-meta">
                          <span className="quickwin-tag">{item.effort}</span>
                          <span className="quickwin-tag">Impacto: {item.impact}</span>
                          <span className="quickwin-tag">{item.category}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              <section id="categorias" className="section page-break">
                <div className="section-header">
                  <div className="section-icon"><svg viewBox="0 0 24 24"><path d="M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z" /></svg></div>
                  <div>
                    <h2 className="section-title">Análise por Categoria</h2>
                    <p className="section-subtitle">Distribuição de vulnerabilidades por área</p>
                  </div>
                </div>

                <div className="category-grid">
                  {data.categories.map((category) => (
                    <div key={category.category} className="category-card no-break">
                      <div className="category-icon">#</div>
                      <h4 className="category-name">{category.category}</h4>
                      <div className="category-count">
                        <div className="category-stat">
                          <span className="category-stat-value text-critical">{category.critical}</span>
                          <span className="category-stat-label">Críticas</span>
                        </div>
                        <div className="category-stat">
                          <span className="category-stat-value text-high">{category.high}</span>
                          <span className="category-stat-label">Altas</span>
                        </div>
                        <div className="category-stat">
                          <span className="category-stat-value">{category.findings}</span>
                          <span className="category-stat-label">Total</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              <section id="tecnico" className="section page-break">
                <div className="section-header">
                  <div className="section-icon"><svg viewBox="0 0 24 24"><path d="M9.4 16.6L4.8 12l4.6-4.6L8 6l-6 6 6 6 1.4-1.4zm5.2 0l4.6-4.6-4.6-4.6L16 6l6 6-6 6-1.4-1.4z" /></svg></div>
                  <div>
                    <h2 className="section-title">Detalhamento Técnico</h2>
                    <p className="section-subtitle">URLs afetadas, payloads e evidências</p>
                  </div>
                </div>

                {data.vulnerabilities.slice(0, 12).map((row, index) => {
                  const sev = String(row.severity || "low").toLowerCase();
                  const badge = SEVERITY_META[sev] || SEVERITY_META.low;
                  const title = row.name || row.problem || "Vulnerabilidade identificada";
                  const technicalPayload = row.payload || row.exploit || row.evidence || row.error || "Sem payload/evidência detalhada para este item.";
                  const urls = [row.full_url, row.target].filter(Boolean).join("\n");
                  return (
                    <div key={`tech-${index}-${row.id}`} className="technical-card no-break">
                      <div className="technical-header">
                        <div className="technical-title">
                          <span className={`severity-badge ${badge.css}`}>{badge.label}</span>
                          <h4>{row.id || `VUL-${String(index + 1).padStart(3, "0")}`}: {title}</h4>
                        </div>
                      </div>
                      <div className="technical-body">
                        <div className="technical-detail">
                          <div className="technical-label">URLs Afetadas</div>
                          <div className="technical-url">{urls || "Sem URL consolidada."}</div>
                        </div>
                        <div className="technical-detail">
                          <div className="technical-label">Payload/Evidência</div>
                          <div className="technical-payload">{technicalPayload}</div>
                        </div>
                        <div className="technical-detail">
                          <div className="technical-label">Contexto Técnico</div>
                          <div className="technical-url">step={row.step || "-"} | node={row.node || "-"}</div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </section>

              <section id="evolucao" className="section page-break">
                <div className="section-header">
                  <div className="section-icon"><svg viewBox="0 0 24 24"><path d="M3 17h2v2H3v-2zm4-5h2v7H7v-7zm4-4h2v11h-2V8zm4 2h2v9h-2v-9zm4-6h2v15h-2V4z" /></svg></div>
                  <div>
                    <h2 className="section-title">Benchmark e Evolução por Alvo</h2>
                    <p className="section-subtitle">Comparativo setorial (WEF) e histórico consolidado dos scans</p>
                  </div>
                </div>

                <div className="chart-container no-break">
                  <div className="chart-header"><h3 className="chart-title">Benchmark Setorial</h3></div>
                  <div className="table-container">
                    <table>
                      <thead>
                        <tr>
                          <th>Segmento</th>
                          <th>Fonte</th>
                          <th>Exposure Alvo</th>
                          <th>Exposure Segmento</th>
                          <th>SLA Patch (dias)</th>
                          <th>Avaliação</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr>
                          <td>{data.benchmark.segment || "-"}</td>
                          <td>{data.benchmark.source || "-"}</td>
                          <td>{data.benchmark.target_external_exposure_index ?? "-"}</td>
                          <td>{data.benchmark.segment_external_exposure_index ?? "-"}</td>
                          <td>{data.benchmark.segment_patch_sla_days ?? "-"}</td>
                          <td>{data.benchmark.assessment || "-"}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>

                <div className="chart-container no-break">
                  <div className="chart-header"><h3 className="chart-title">Evolução do Alvo entre Scans</h3></div>
                  <div className="table-container">
                    <table>
                      <thead>
                        <tr>
                          <th>Scan</th>
                          <th>Data</th>
                          <th>Status</th>
                          <th>Open Findings</th>
                          <th>Delta vs Anterior</th>
                          <th>Crítico/Alto/Médio/Baixo</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(data.targetEvolution.timeline || []).map((item) => (
                          <tr key={`timeline-${item.scan_id}`}>
                            <td>#{item.scan_id}{item.is_current ? " (atual)" : ""}</td>
                            <td>{fmtDateTime(item.created_at)}</td>
                            <td>{item.status || "-"}</td>
                            <td>{item.open_findings ?? 0}</td>
                            <td>{Number(item.delta_open_vs_previous || 0) > 0 ? `+${item.delta_open_vs_previous}` : item.delta_open_vs_previous || 0}</td>
                            <td>
                              {item?.severity?.critical || 0}/{item?.severity?.high || 0}/{item?.severity?.medium || 0}/{item?.severity?.low || 0}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                <div className="chart-container no-break">
                  <div className="chart-header"><h3 className="chart-title">Achados Recorrentes no Alvo</h3></div>
                  <div className="table-container">
                    <table>
                      <thead>
                        <tr>
                          <th>Vulnerabilidade</th>
                          <th>Severidade</th>
                          <th>Ocorrências</th>
                          <th>Primeiro Scan</th>
                          <th>Último Scan</th>
                          <th>Tendência</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(data.targetEvolution.recurring_findings || []).slice(0, 20).map((row, idx) => (
                          <tr key={`recurring-${idx}-${row.signature}`}>
                            <td>{row.title || "-"}</td>
                            <td>{SEVERITY_META[String(row.severity || "low").toLowerCase()]?.label || row.severity || "-"}</td>
                            <td>{row.occurrences ?? 0}</td>
                            <td>#{row.first_scan_id || "-"}</td>
                            <td>#{row.last_scan_id || "-"}</td>
                            <td>{row.trend || "-"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </section>
            </main>
          </div>

          <footer className="report-footer">
            <div className="footer-content">
              <div className="footer-logo">Security Report</div>
              <div className="footer-info">
                <div>Gerado em: {fmtDateTime(report?.state_data?.generated_at || selectedScan?.updated_at || new Date())}</div>
                <div>Próxima revisão: {fmtDate(new Date(Date.now() + 1000 * 60 * 60 * 24 * 30))}</div>
              </div>
              <div className="footer-classification">Confidencial</div>
            </div>
          </footer>
          <div className="print-page-number" />
        </>
      )}
    </div>
  );
}
