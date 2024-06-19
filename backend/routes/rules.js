const express = require('express');
const axios = require('axios');
const router = express.Router();

const KIBANA_URL = process.env.KIBANA_URL;
const KIBANA_USERNAME = process.env.KIBANA_USERNAME;
const KIBANA_PASSWORD = process.env.KIBANA_PASSWORD;

// Fetch all rules
router.get('/', async (req, res) => {
  try {
    const response = await axios.get(`${KIBANA_URL}/api/alerting/rules/_find`, {
      headers: {
        'kbn-xsrf': 'true',
      },
      auth: {
        username: KIBANA_USERNAME,
        password: KIBANA_PASSWORD,
      },
    });
    res.json(response.data);
  } catch (error) {
    console.error('Error fetching rules:', error);
    res.status(500).json({ error: error.message });
  }
});

// Update a specific rule
router.put('/:ruleId', async (req, res) => {
  const { ruleId } = req.params;
  const {
    name,
    tags,
    params,
    schedule,
    actions,
    throttle,
    notify_when,
  } = req.body;

  const ruleData = {
    name: name || 'SQL Injection',
    tags: tags || [],
    params: {
      author: params.author || [],
      description: params.description || 'SQL Injection',
      falsePositives: params.falsePositives || [],
      from: params.from || 'now-360s',
      ruleId: params.ruleId || '297aa6fb-54d1-4eb5-94f0-edf95524dd37',
      immutable: params.immutable !== undefined ? params.immutable : false,
      index: params.index || ['snort-logs-*'],
      license: params.license || '',
      outputIndex: params.outputIndex || '',
      meta: params.meta || {},
      maxSignals: params.maxSignals || 100,
      riskScore: params.riskScore || 99,
      riskScoreMapping: params.riskScoreMapping || [],
      severity: params.severity || 'critical',
      severityMapping: params.severityMapping || [],
      threat: params.threat || [],
      to: params.to || 'now',
      references: params.references || [],
      version: params.version || 1,
      exceptionsList: params.exceptionsList || [],
      relatedIntegrations: params.relatedIntegrations || [],
      requiredFields: params.requiredFields || [],
      setup: params.setup || '',
      type: params.type || 'query',
      language: params.language || 'kuery',
      query: params.query || 'event.original : *SQL Injection*',
      filters: params.filters || [],
      dataViewId: params.dataViewId || '',
    },
    schedule: schedule || { interval: '1m' },
    actions: actions || [{
      group: 'default',
      id: '8aa88aab-3578-4f0f-998a-357187dfb822', // Replace with your connector ID
      params: {
        level: 'info',
        body: '{ "Alert": "{{context.alerts}}" }',
      },
    }],
    throttle: throttle || null,
    notify_when: notify_when || 'onActionGroupChange',
  };

  console.log('Updating rule with data:', JSON.stringify(ruleData, null, 2));

  try {
    const response = await axios.put(
      `${KIBANA_URL}/api/alerting/rule/${ruleId}`,
      ruleData,
      {
        headers: {
          'kbn-xsrf': 'true',
        },
        auth: {
          username: KIBANA_USERNAME,
          password: KIBANA_PASSWORD,
        },
      }
    );
    res.json(response.data);
  } catch (error) {
    console.error(`Error updating rule ${ruleId}:`, error.response ? error.response.data : error.message);
    res.status(500).json(error.response ? error.response.data : { error: error.message });
  }
});

module.exports = router;
