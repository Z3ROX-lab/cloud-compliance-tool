import React, { useState } from 'react';
import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

function ArchitectureView() {
  const [resources, setResources] = useState(null);
  const [loading, setLoading] = useState(false);
  const [selectedType, setSelectedType] = useState('all');
  const [provider, setProvider] = useState('aws');
  const [region, setRegion] = useState('eu-west-1');

  const scanResources = async () => {
    setLoading(true);
    try {
      const response = await axios.post(`${API_URL}/api/v1/cloud-accounts/scan`, null, {
        params: { provider, region }
      });
      setResources(response.data);
    } catch (error) {
      console.error('Failed to scan resources:', error);
    } finally {
      setLoading(false);
    }
  };

  const getResourceIcon = (type) => {
    const icons = {
      // AWS
      'ec2_instances': '🖥️',
      's3_buckets': '🪣',
      'iam_users': '👤',
      'iam_roles': '🎭',
      'vpc': '🌐',
      'security_groups': '🛡️',
      'cloudtrail': '📝',
      'rds_instances': '🗄️',
      'lambda_functions': 'λ',
      'ebs_volumes': '💾',
      'kms_keys': '🔑',
      'load_balancers': '⚖️',
      // Azure
      'virtual_machines': '🖥️',
      'storage_accounts': '💾',
      'sql_databases': '🗄️',
      'network_security_groups': '🛡️',
      'virtual_networks': '🌐',
      'key_vaults': '🔐',
      'aks_clusters': '☸️',
      'disks': '💿',
      'public_ips': '🌍',
      // GCP
      'compute_instances': '🖥️',
      'storage_buckets': '🪣',
      'gke_clusters': '☸️',
      'vpc_networks': '🌐',
      'firewall_rules': '🛡️',
      'compute_disks': '💿',
      'sql_instances': '🗄️',
      // Kubernetes
      'namespaces': '📦',
      'pods': '🐳',
      'deployments': '🚀',
      'services': '🔌',
      'ingresses': '🚪',
      'configmaps': '⚙️',
      'secrets': '🔒',
      'persistent_volumes': '💾',
      'persistent_volume_claims': '📋',
      'service_accounts': '👤',
      'roles': '🎭',
      'role_bindings': '🔗',
      'cluster_roles': '👑',
      'cluster_role_bindings': '🔗',
      'network_policies': '🛡️',
      'storage_classes': '💿',
    };
    return icons[type] || '📦';
  };

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-lg shadow-md p-6">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">
          Visualisation de l'Architecture
        </h1>
        <p className="text-gray-600">
          Cartographie interactive de vos ressources cloud
        </p>
      </div>

      {!resources && (
        <div className="bg-white rounded-lg shadow-md p-6">
          <div className="text-center py-6">
            <span className="text-6xl mb-4 block">🏗️</span>
            <h2 className="text-2xl font-bold text-gray-900 mb-2">
              Découvrir votre Infrastructure
            </h2>
            <p className="text-gray-600 mb-6">
              Scannez votre compte cloud pour visualiser toutes vos ressources
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 max-w-2xl mx-auto mb-6">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2 text-left">
                  Fournisseur Cloud
                </label>
                <select
                  value={provider}
                  onChange={(e) => setProvider(e.target.value)}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  <option value="aws">☁️ AWS</option>
                  <option value="azure">☁️ Azure</option>
                  <option value="gcp">☁️ GCP</option>
                  <option value="kubernetes">☸️ Kubernetes</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2 text-left">
                  Région
                </label>
                <select
                  value={region}
                  onChange={(e) => setRegion(e.target.value)}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  <option value="eu-west-1">EU West 1</option>
                  <option value="eu-west-3">EU West 3</option>
                  <option value="eu-central-1">EU Central 1</option>
                  <option value="us-east-1">US East 1</option>
                </select>
              </div>
            </div>

            <button
              onClick={scanResources}
              disabled={loading}
              className="bg-blue-600 text-white px-8 py-3 rounded-lg hover:bg-blue-700 transition-colors disabled:bg-gray-400 font-semibold"
            >
              {loading ? 'Scan en cours...' : '🔍 Lancer le Scan'}
            </button>
          </div>
        </div>
      )}

      {resources && (
        <>
          <div className="bg-white rounded-lg shadow-md p-6">
            <h2 className="text-2xl font-bold text-gray-900 mb-4">
              Ressources Découvertes
            </h2>
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
              {Object.entries(resources.resources_discovered).map(([type, count]) => (
                <div
                  key={type}
                  className="bg-gradient-to-br from-blue-50 to-blue-100 rounded-lg p-4 text-center hover:shadow-lg transition-shadow cursor-pointer"
                  onClick={() => setSelectedType(type)}
                >
                  <div className="text-3xl mb-2">{getResourceIcon(type)}</div>
                  <div className="text-2xl font-bold text-blue-900">{count}</div>
                  <div className="text-xs text-blue-700 mt-1">{type.replace(/_/g, ' ')}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-white rounded-lg shadow-md p-6">
            <h2 className="text-xl font-bold text-gray-900 mb-4">
              Détails des Ressources {selectedType !== 'all' && `- ${selectedType}`}
            </h2>
            <div className="max-h-96 overflow-y-auto space-y-2">
              {selectedType === 'all' ? (
                <p className="text-gray-600">Sélectionnez un type de ressource ci-dessus</p>
              ) : (
                resources.resources[selectedType]?.map((resource, index) => (
                  <div key={index} className="p-4 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors">
                    <div className="flex items-center justify-between">
                      <div className="flex-1">
                        <div className="font-semibold text-gray-900">
                          {resource.resource_name || resource.resource_id}
                        </div>
                        <div className="text-sm text-gray-600">
                          {resource.resource_type} • {resource.region}
                        </div>
                      </div>
                      <div className="text-2xl">{getResourceIcon(selectedType)}</div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

export default ArchitectureView;
