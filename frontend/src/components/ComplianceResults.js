import React from 'react';

function ComplianceResults() {
  return (
    <div className="space-y-6">
      <div className="bg-white rounded-lg shadow-md p-6">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">
          Résultats de Conformité
        </h1>
        <p className="text-gray-600">
          Consultez l'historique et les détails de vos audits
        </p>
      </div>

      <div className="bg-white rounded-lg shadow-md p-6">
        <div className="text-center py-12">
          <span className="text-6xl mb-4 block">📊</span>
          <h2 className="text-2xl font-bold text-gray-900 mb-2">
            Historique des Audits
          </h2>
          <p className="text-gray-600 mb-4">
            Les résultats de vos audits précédents apparaîtront ici
          </p>
          <p className="text-sm text-gray-500">
            Lancez un audit depuis la page "Lancer Audit" pour voir les résultats
          </p>
        </div>
      </div>
    </div>
  );
}

export default ComplianceResults;
