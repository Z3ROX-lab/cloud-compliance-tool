import React from 'react';

function Reports() {
  return (
    <div className="space-y-6">
      <div className="bg-white rounded-lg shadow-md p-6">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">
          Rapports de Conformité
        </h1>
        <p className="text-gray-600">
          Générez et exportez vos rapports d'audit
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-white rounded-lg shadow-md p-6 hover:shadow-lg transition-shadow">
          <div className="text-center">
            <div className="text-5xl mb-4">📄</div>
            <h3 className="text-xl font-bold text-gray-900 mb-2">Rapport PDF</h3>
            <p className="text-gray-600 text-sm mb-4">
              Rapport détaillé avec graphiques et recommandations
            </p>
            <button
              disabled
              className="bg-gray-400 text-white px-6 py-2 rounded-lg cursor-not-allowed"
            >
              Bientôt disponible
            </button>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-md p-6 hover:shadow-lg transition-shadow">
          <div className="text-center">
            <div className="text-5xl mb-4">📊</div>
            <h3 className="text-xl font-bold text-gray-900 mb-2">Export Excel</h3>
            <p className="text-gray-600 text-sm mb-4">
              Tableau détaillé de toutes les vérifications
            </p>
            <button
              disabled
              className="bg-gray-400 text-white px-6 py-2 rounded-lg cursor-not-allowed"
            >
              Bientôt disponible
            </button>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-md p-6 hover:shadow-lg transition-shadow">
          <div className="text-center">
            <div className="text-5xl mb-4">🔗</div>
            <h3 className="text-xl font-bold text-gray-900 mb-2">Export JSON</h3>
            <p className="text-gray-600 text-sm mb-4">
              Données brutes pour intégration avec d'autres outils
            </p>
            <button
              disabled
              className="bg-gray-400 text-white px-6 py-2 rounded-lg cursor-not-allowed"
            >
              Bientôt disponible
            </button>
          </div>
        </div>
      </div>

      <div className="bg-blue-50 border-l-4 border-blue-500 p-4 rounded">
        <div className="flex">
          <div className="flex-shrink-0">
            <span className="text-2xl">ℹ️</span>
          </div>
          <div className="ml-3">
            <h3 className="text-sm font-medium text-blue-800">
              Génération de rapports en développement
            </h3>
            <div className="mt-2 text-sm text-blue-700">
              La fonctionnalité de génération de rapports sera disponible dans une prochaine version.
              Les rapports incluront des analyses détaillées, des recommandations de remédiation et des preuves de conformité.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Reports;
