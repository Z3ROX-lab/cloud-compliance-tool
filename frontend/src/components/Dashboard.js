import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

function Dashboard() {
  const [complianceData, setComplianceData] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchComplianceOverview = async () => {
    setLoading(true);
    try {
      const response = await axios.get(`${API_URL}/api/v1/stats/compliance-overview`);
      setComplianceData(response.data);
    } catch (error) {
      console.error('Failed to fetch compliance overview:', error);
    } finally {
      setLoading(false);
    }
  };

  const getScoreColor = (score) => {
    if (score >= 80) return 'text-green-600';
    if (score >= 60) return 'text-yellow-600';
    return 'text-red-600';
  };

  const getScoreBgColor = (score) => {
    if (score >= 80) return 'bg-green-100';
    if (score >= 60) return 'bg-yellow-100';
    return 'bg-red-100';
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white rounded-lg shadow-md p-6">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">
          Cloud Compliance Dashboard
        </h1>
        <p className="text-gray-600">
          Auditez la conformité NIS2 et SecNumCloud de vos infrastructures cloud en temps réel
        </p>
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Link
          to="/audit"
          className="bg-gradient-to-r from-blue-500 to-blue-600 text-white rounded-lg shadow-lg p-6 hover:from-blue-600 hover:to-blue-700 transition-all transform hover:scale-105"
        >
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-xl font-semibold mb-2">Lancer un Audit</h3>
              <p className="text-blue-100">Démarrer une analyse complète</p>
            </div>
            <span className="text-4xl">🔍</span>
          </div>
        </Link>

        <Link
          to="/architecture"
          className="bg-gradient-to-r from-purple-500 to-purple-600 text-white rounded-lg shadow-lg p-6 hover:from-purple-600 hover:to-purple-700 transition-all transform hover:scale-105"
        >
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-xl font-semibold mb-2">Visualiser l'Archi</h3>
              <p className="text-purple-100">Carte interactive des ressources</p>
            </div>
            <span className="text-4xl">🏗️</span>
          </div>
        </Link>

        <Link
          to="/reports"
          className="bg-gradient-to-r from-green-500 to-green-600 text-white rounded-lg shadow-lg p-6 hover:from-green-600 hover:to-green-700 transition-all transform hover:scale-105"
        >
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-xl font-semibold mb-2">Générer Rapport</h3>
              <p className="text-green-100">Export PDF/Excel</p>
            </div>
            <span className="text-4xl">📄</span>
          </div>
        </Link>
      </div>

      {/* Compliance Overview */}
      {!complianceData && (
        <div className="bg-white rounded-lg shadow-md p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-2xl font-bold text-gray-900">Vue d'ensemble de la conformité</h2>
            <button
              onClick={fetchComplianceOverview}
              disabled={loading}
              className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors disabled:bg-gray-400"
            >
              {loading ? 'Chargement...' : 'Charger les données'}
            </button>
          </div>
          <p className="text-gray-600">
            Cliquez sur "Charger les données" pour analyser votre infrastructure cloud
          </p>
        </div>
      )}

      {complianceData && (
        <>
          {/* Global Score */}
          <div className="bg-white rounded-lg shadow-md p-6">
            <h2 className="text-2xl font-bold text-gray-900 mb-4">Score Global de Conformité</h2>
            <div className="flex items-center justify-center">
              <div className={`relative w-48 h-48 rounded-full ${getScoreBgColor(complianceData.global_compliance_score)} flex items-center justify-center`}>
                <div className="text-center">
                  <div className={`text-6xl font-bold ${getScoreColor(complianceData.global_compliance_score)}`}>
                    {Math.round(complianceData.global_compliance_score)}%
                  </div>
                  <div className="text-gray-600 text-sm mt-2">Conformité Globale</div>
                </div>
              </div>
            </div>
            <div className="mt-4 text-center text-gray-600">
              {complianceData.total_resources} ressources analysées
            </div>
          </div>

          {/* Framework Scores */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {Object.entries(complianceData.frameworks).map(([framework, data]) => (
              <div key={framework} className="bg-white rounded-lg shadow-md p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-xl font-bold text-gray-900">{framework}</h3>
                  <span className={`text-3xl font-bold ${getScoreColor(data.compliance_score)}`}>
                    {Math.round(data.compliance_score)}%
                  </span>
                </div>

                <div className="space-y-3">
                  <div className="flex justify-between items-center">
                    <span className="text-gray-600">Vérifications totales</span>
                    <span className="font-semibold">{data.total_checks}</span>
                  </div>

                  <div className="flex justify-between items-center">
                    <span className="text-green-600">✓ Conformes</span>
                    <span className="font-semibold text-green-600">{data.passed_checks}</span>
                  </div>

                  <div className="flex justify-between items-center">
                    <span className="text-red-600">✗ Non conformes</span>
                    <span className="font-semibold text-red-600">{data.failed_checks}</span>
                  </div>

                  <div className="flex justify-between items-center">
                    <span className="text-yellow-600">⚠ Avertissements</span>
                    <span className="font-semibold text-yellow-600">{data.warning_checks}</span>
                  </div>
                </div>

                {/* Progress Bar */}
                <div className="mt-4 w-full bg-gray-200 rounded-full h-2">
                  <div
                    className={`h-2 rounded-full ${
                      data.compliance_score >= 80
                        ? 'bg-green-600'
                        : data.compliance_score >= 60
                        ? 'bg-yellow-600'
                        : 'bg-red-600'
                    }`}
                    style={{ width: `${data.compliance_score}%` }}
                  ></div>
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {/* Key Features */}
      <div className="bg-white rounded-lg shadow-md p-6">
        <h2 className="text-2xl font-bold text-gray-900 mb-4">Fonctionnalités Clés</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="text-center p-4">
            <div className="text-4xl mb-2">🔐</div>
            <h3 className="font-semibold text-lg mb-2">Multi-Framework</h3>
            <p className="text-gray-600 text-sm">
              Support NIS2, SecNumCloud, ISO 27001, RGPD
            </p>
          </div>

          <div className="text-center p-4">
            <div className="text-4xl mb-2">☁️</div>
            <h3 className="font-semibold text-lg mb-2">Multi-Cloud</h3>
            <p className="text-gray-600 text-sm">
              AWS, Azure, GCP, OVH, Scaleway
            </p>
          </div>

          <div className="text-center p-4">
            <div className="text-4xl mb-2">🤖</div>
            <h3 className="font-semibold text-lg mb-2">Automatisation</h3>
            <p className="text-gray-600 text-sm">
              Scans planifiés, alertes temps réel
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;
