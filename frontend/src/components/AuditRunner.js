import React, { useState } from 'react';
import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

function AuditRunner() {
  const [framework, setFramework] = useState('NIS2');
  const [provider, setProvider] = useState('aws');
  const [region, setRegion] = useState('eu-west-1');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const runAudit = async () => {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await axios.post(`${API_URL}/api/v1/audits/run`, null, {
        params: { framework, provider, region }
      });
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to run audit');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-lg shadow-md p-6">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">Lancer un Audit de Conformité</h1>
        <p className="text-gray-600">Configurez et exécutez un audit complet de votre infrastructure</p>
      </div>

      <div className="bg-white rounded-lg shadow-md p-6">
        <h2 className="text-xl font-bold text-gray-900 mb-4">Configuration de l'Audit</h2>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Référentiel de Conformité
            </label>
            <select
              value={framework}
              onChange={(e) => setFramework(e.target.value)}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="NIS2">NIS2 - Directive EU</option>
              <option value="SecNumCloud">SecNumCloud - ANSSI</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Fournisseur Cloud
            </label>
            <select
              value={provider}
              onChange={(e) => setProvider(e.target.value)}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="aws">Amazon Web Services (AWS)</option>
              <option value="azure" disabled>Microsoft Azure (Bientôt)</option>
              <option value="gcp" disabled>Google Cloud Platform (Bientôt)</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Région
            </label>
            <select
              value={region}
              onChange={(e) => setRegion(e.target.value)}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="eu-west-1">EU West 1 (Irlande)</option>
              <option value="eu-west-3">EU West 3 (Paris)</option>
              <option value="eu-central-1">EU Central 1 (Francfort)</option>
            </select>
          </div>
        </div>

        <button
          onClick={runAudit}
          disabled={loading}
          className="mt-6 w-full bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition-colors disabled:bg-gray-400 font-semibold text-lg"
        >
          {loading ? '🔍 Audit en cours...' : '▶️ Démarrer l\'Audit'}
        </button>
      </div>

      {error && (
        <div className="bg-red-50 border-l-4 border-red-500 p-4 rounded">
          <div className="flex">
            <div className="flex-shrink-0">
              <span className="text-2xl">❌</span>
            </div>
            <div className="ml-3">
              <h3 className="text-sm font-medium text-red-800">Erreur lors de l'audit</h3>
              <div className="mt-2 text-sm text-red-700">{error}</div>
            </div>
          </div>
        </div>
      )}

      {result && (
        <div className="bg-white rounded-lg shadow-md p-6">
          <h2 className="text-2xl font-bold text-gray-900 mb-4">Résultats de l'Audit</h2>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-6">
            <div className="bg-blue-50 rounded-lg p-4">
              <div className="text-sm text-blue-600 font-medium">Framework</div>
              <div className="text-2xl font-bold text-blue-900">{result.summary.framework}</div>
            </div>

            <div className="bg-green-50 rounded-lg p-4">
              <div className="text-sm text-green-600 font-medium">Score</div>
              <div className="text-2xl font-bold text-green-900">{Math.round(result.summary.compliance_score)}%</div>
            </div>

            <div className="bg-gray-50 rounded-lg p-4">
              <div className="text-sm text-gray-600 font-medium">Total</div>
              <div className="text-2xl font-bold text-gray-900">{result.summary.total_checks}</div>
            </div>

            <div className="bg-green-50 rounded-lg p-4">
              <div className="text-sm text-green-600 font-medium">✓ Conformes</div>
              <div className="text-2xl font-bold text-green-900">{result.summary.passed_checks}</div>
            </div>

            <div className="bg-red-50 rounded-lg p-4">
              <div className="text-sm text-red-600 font-medium">✗ Échecs</div>
              <div className="text-2xl font-bold text-red-900">{result.summary.failed_checks}</div>
            </div>
          </div>

          <div className="border-t pt-4">
            <h3 className="font-bold text-lg mb-2">Détails des vérifications</h3>
            <div className="max-h-96 overflow-y-auto space-y-2">
              {result.audit.results.slice(0, 20).map((check, index) => (
                <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded">
                  <div className="flex-1">
                    <div className="font-medium">{check.resource_name || check.resource_id}</div>
                    <div className="text-sm text-gray-600">{check.resource_type} - {check.rule_id}</div>
                  </div>
                  <div>
                    {check.status === 'compliant' && <span className="text-green-600 font-bold">✓</span>}
                    {check.status === 'non_compliant' && <span className="text-red-600 font-bold">✗</span>}
                    {check.status === 'warning' && <span className="text-yellow-600 font-bold">⚠</span>}
                  </div>
                </div>
              ))}
            </div>
            {result.audit.results.length > 20 && (
              <p className="text-sm text-gray-500 mt-2">
                Affichage de 20 sur {result.audit.results.length} résultats...
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default AuditRunner;
