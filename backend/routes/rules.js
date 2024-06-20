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
                'kbn-xsrf': 'true'
            },
            auth: {
                username: KIBANA_USERNAME,
                password: KIBANA_PASSWORD
            }
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
        notifyWhen
    } = req.body;

    const defaultParams = {
        author: [],
        description: 'SQL Injection',
        falsePositives: [],
        from: 'now-360s',
        ruleId: '297aa6fb-54d1-4eb5-94f0-edf95524dd37',
        immutable: false,
        license: '',
        outputIndex: '',
        meta: {},
        maxSignals: 100,
        riskScore: 99,
        riskScoreMapping: [],
        severity: 'critical',
        severityMapping: [],
        threat: [],
        to: 'now',
        references: [],
        version: 1,
        exceptionsList: [],
        relatedIntegrations: [],
        requiredFields: [],
        setup: '',
        type: 'query',
        language: 'kuery',
        query: 'event.original : *SQL Injection*',
        filters: [],
        dataViewId: '',
        index: ['snort-logs-*'],
        timeField: '@timestamp'
    };

    const mergedParams = { ...defaultParams, ...params };

    // Ensure description is at least 1 character long
    if (!mergedParams.description || mergedParams.description.length < 1) {
        mergedParams.description = 'Default Description';
    }

    const ruleData = {
        name: name || 'SQL Injection',
        tags: tags || [],
        params: mergedParams,
        schedule: schedule || { interval: '1m' },
        actions: actions || [],
        throttle: throttle || null,
        notify_when: notifyWhen || 'onActionGroupChange'
    };

    console.log('Updating rule with data:', JSON.stringify(ruleData, null, 2));

    try {
        const response = await axios.put(
            `${KIBANA_URL}/api/alerting/rule/${ruleId}`,
            ruleData,
            {
                headers: {
                    'kbn-xsrf': 'true'
                },
                auth: {
                    username: KIBANA_USERNAME,
                    password: KIBANA_PASSWORD
                }
            }
        );
        res.json(response.data);
    } catch (error) {
        console.error(`Error updating rule ${ruleId}:`, error.response ? error.response.data : error.message);
        res.status(500).json(error.response ? error.response.data : { error: error.message });
    }
});

// Create a new rule
router.post('/', async (req, res) => {
    const {
        name,
        tags,
        params,
        schedule,
        actions,
        throttle,
        notify_when,
        rule_type_id,
        consumer
    } = req.body;

    const defaultParams = {
        author: [],
        description: 'New rule description',
        falsePositives: [],
        from: 'now-360s',
        ruleId: 'new-rule-id',
        immutable: false,
        license: '',
        outputIndex: '',
        meta: {},
        maxSignals: 100,
        riskScore: 50,
        riskScoreMapping: [],
        severity: 'medium',
        severityMapping: [],
        threat: [],
        to: 'now',
        references: [],
        version: 1,
        exceptionsList: [],
        relatedIntegrations: [],
        requiredFields: [],
        setup: '',
        type: 'query',
        language: 'kuery',
        query: '',
        filters: [],
        dataViewId: '',
        index: ['snort-logs-*'],
        timeField: '@timestamp'
    };

    const mergedParams = { ...defaultParams, ...params };

    // Ensure description is at least 1 character long
    if (!mergedParams.description || mergedParams.description.length < 1) {
        mergedParams.description = 'Default Description';
    }

    const ruleData = {
        name: name || 'New Rule',
        tags: tags || [],
        params: mergedParams,
        schedule: schedule || { interval: '1m' },
        actions: actions || [],
        throttle: throttle || null,
        notify_when: notify_when || 'onActionGroupChange',
        rule_type_id: rule_type_id || 'siem.queryRule',
        consumer: consumer || 'alerts'
    };

    console.log('Creating rule with data:', JSON.stringify(ruleData, null, 2));

    try {
        const response = await axios.post(
            `${KIBANA_URL}/api/alerting/rule`,
            ruleData,
            {
                headers: {
                    'kbn-xsrf': 'true'
                },
                auth: {
                    username: KIBANA_USERNAME,
                    password: KIBANA_PASSWORD
                }
            }
        );
        res.json(response.data);
    } catch (error) {
        console.error('Error creating rule:', error.response ? error.response.data : error.message);
        res.status(500).json(error.response ? error.response.data : { error: error.message });
    }
});

module.exports = router;
