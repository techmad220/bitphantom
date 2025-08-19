const tf = require('@tensorflow/tfjs-node');
const EventEmitter = require('events');

class AnomalyDetector extends EventEmitter {
    constructor(config = {}) {
        super();
        
        this.config = {
            modelType: 'autoencoder', // 'autoencoder', 'isolation-forest', 'one-class-svm'
            threshold: 0.85,
            batchSize: 32,
            epochs: 10,
            learningRate: 0.001,
            inputDim: 50,
            encodingDim: 16,
            memoryLimit: 512 * 1024 * 1024, // 512MB max memory
            updateInterval: 3600000, // 1 hour
            minTrainingData: 1000,
            maxTrainingData: 10000,
            features: [
                'method', 'path_length', 'query_count', 'header_count',
                'body_size', 'special_chars', 'sql_keywords', 'xss_patterns',
                'request_rate', 'unique_params', 'encoding_type'
            ],
            ...config
        };
        
        this.model = null;
        this.encoder = null;
        this.decoder = null;
        this.scaler = null;
        this.trainingData = [];
        this.isTraining = false;
        this.stats = {
            totalAnalyzed: 0,
            anomaliesDetected: 0,
            modelUpdates: 0,
            accuracy: 0,
            lastTraining: null
        };
        
        // Feature extraction patterns
        this.patterns = {
            sqlKeywords: /\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|EXEC)\b/gi,
            xssPatterns: /<[^>]*>|javascript:|on\w+=/gi,
            specialChars: /[<>'"`;(){}[\]]/g,
            encodedChars: /%[0-9a-f]{2}/gi,
            base64: /^[A-Za-z0-9+/]+=*$/
        };
    }

    async initialize() {
        try {
            // Set memory constraints
            tf.engine().startScope();
            tf.env().set('WEBGL_PACK', false);
            tf.env().set('WEBGL_FORCE_F16_TEXTURES', true);
            
            // Build initial model
            await this.buildModel();
            
            // Load pre-trained weights if available
            await this.loadModel();
            
            // Start periodic training
            this.startTrainingSchedule();
            
            console.log('[AI Anomaly Detector] Initialized with', this.config.modelType);
            return true;
        } catch (error) {
            console.error('[AI Anomaly Detector] Initialization error:', error);
            throw error;
        }
    }

    async buildModel() {
        switch (this.config.modelType) {
            case 'autoencoder':
                await this.buildAutoencoder();
                break;
            case 'isolation-forest':
                await this.buildIsolationForest();
                break;
            case 'one-class-svm':
                await this.buildOneClassSVM();
                break;
            default:
                await this.buildAutoencoder();
        }
    }

    async buildAutoencoder() {
        // Encoder
        const encoder = tf.sequential({
            layers: [
                tf.layers.dense({
                    inputShape: [this.config.inputDim],
                    units: 32,
                    activation: 'relu',
                    kernelInitializer: 'glorotNormal'
                }),
                tf.layers.dropout({ rate: 0.2 }),
                tf.layers.dense({
                    units: this.config.encodingDim,
                    activation: 'relu'
                })
            ]
        });

        // Decoder
        const decoder = tf.sequential({
            layers: [
                tf.layers.dense({
                    inputShape: [this.config.encodingDim],
                    units: 32,
                    activation: 'relu',
                    kernelInitializer: 'glorotNormal'
                }),
                tf.layers.dropout({ rate: 0.2 }),
                tf.layers.dense({
                    units: this.config.inputDim,
                    activation: 'sigmoid'
                })
            ]
        });

        // Full autoencoder
        const input = tf.input({ shape: [this.config.inputDim] });
        const encoded = encoder.apply(input);
        const decoded = decoder.apply(encoded);
        
        this.model = tf.model({ inputs: input, outputs: decoded });
        this.encoder = encoder;
        this.decoder = decoder;

        // Compile model
        this.model.compile({
            optimizer: tf.train.adam(this.config.learningRate),
            loss: 'meanSquaredError',
            metrics: ['accuracy']
        });

        // Initialize scaler
        this.scaler = {
            mean: tf.zeros([this.config.inputDim]),
            std: tf.ones([this.config.inputDim])
        };
    }

    async buildIsolationForest() {
        // Simplified Isolation Forest implementation
        this.isolationTrees = [];
        this.numTrees = 100;
        this.sampleSize = 256;
        
        // Build trees will happen during training
        this.model = {
            predict: (input) => this.isolationForestPredict(input)
        };
    }

    async buildOneClassSVM() {
        // Simplified One-Class SVM using RBF kernel approximation
        this.model = tf.sequential({
            layers: [
                tf.layers.dense({
                    inputShape: [this.config.inputDim],
                    units: 100,
                    activation: 'tanh',
                    kernelInitializer: 'glorotNormal'
                }),
                tf.layers.dense({
                    units: 1,
                    activation: 'tanh'
                })
            ]
        });

        this.model.compile({
            optimizer: tf.train.adam(this.config.learningRate),
            loss: (yTrue, yPred) => {
                // Custom one-class SVM loss
                return tf.mean(tf.maximum(0, tf.sub(1, yPred)));
            }
        });
    }

    async analyze(request) {
        try {
            // Extract features
            const features = await this.extractFeatures(request);
            
            // Check if model is ready
            if (!this.model || this.isTraining) {
                return { isAnomaly: false, score: 0, reason: 'Model not ready' };
            }
            
            // Normalize features
            const normalizedFeatures = await this.normalizeFeatures(features);
            
            // Predict
            const anomalyScore = await this.predict(normalizedFeatures);
            
            // Determine if anomaly
            const isAnomaly = anomalyScore > this.config.threshold;
            
            // Update stats
            this.stats.totalAnalyzed++;
            if (isAnomaly) {
                this.stats.anomaliesDetected++;
            }
            
            // Store for training
            this.addTrainingData(features, isAnomaly);
            
            return {
                isAnomaly,
                score: anomalyScore,
                features: this.getTopFeatures(features, normalizedFeatures),
                confidence: this.calculateConfidence(anomalyScore)
            };
        } catch (error) {
            console.error('[AI Anomaly Detector] Analysis error:', error);
            return { isAnomaly: false, score: 0, error: error.message };
        }
    }

    async extractFeatures(request) {
        const features = [];
        
        // Method encoding (GET=0, POST=1, PUT=2, DELETE=3, etc.)
        const methodMap = { GET: 0, POST: 1, PUT: 2, DELETE: 3, PATCH: 4, HEAD: 5, OPTIONS: 6 };
        features.push(methodMap[request.method] || 7);
        
        // Path characteristics
        features.push(request.path ? request.path.length : 0);
        features.push(request.path ? request.path.split('/').length : 0);
        features.push(request.path ? (request.path.match(/\./g) || []).length : 0);
        
        // Query parameters
        const queryCount = request.query ? Object.keys(request.query).length : 0;
        features.push(queryCount);
        features.push(request.query ? JSON.stringify(request.query).length : 0);
        
        // Headers
        const headerCount = request.headers ? Object.keys(request.headers).length : 0;
        features.push(headerCount);
        
        // User-Agent characteristics
        const ua = request.headers?.['user-agent'] || '';
        features.push(ua.length);
        features.push(ua.includes('bot') ? 1 : 0);
        features.push(ua.includes('crawler') ? 1 : 0);
        
        // Body characteristics
        const bodyStr = JSON.stringify(request.body || {});
        features.push(bodyStr.length);
        
        // Security patterns
        features.push((bodyStr.match(this.patterns.sqlKeywords) || []).length);
        features.push((bodyStr.match(this.patterns.xssPatterns) || []).length);
        features.push((bodyStr.match(this.patterns.specialChars) || []).length);
        features.push((bodyStr.match(this.patterns.encodedChars) || []).length);
        
        // Content type
        const contentType = request.headers?.['content-type'] || '';
        features.push(contentType.includes('json') ? 1 : 0);
        features.push(contentType.includes('xml') ? 1 : 0);
        features.push(contentType.includes('form') ? 1 : 0);
        
        // Time-based features
        const hour = new Date().getHours();
        features.push(Math.sin(2 * Math.PI * hour / 24)); // Cyclical encoding
        features.push(Math.cos(2 * Math.PI * hour / 24));
        
        // Request rate (would need historical data)
        features.push(request.requestRate || 0);
        
        // Pad or truncate to inputDim
        while (features.length < this.config.inputDim) {
            features.push(0);
        }
        
        return features.slice(0, this.config.inputDim);
    }

    async normalizeFeatures(features) {
        // Z-score normalization
        const tensor = tf.tensor2d([features]);
        
        if (this.scaler && this.scaler.mean && this.scaler.std) {
            const normalized = tensor.sub(this.scaler.mean).div(this.scaler.std.add(1e-8));
            const result = await normalized.array();
            normalized.dispose();
            tensor.dispose();
            return result[0];
        }
        
        tensor.dispose();
        return features;
    }

    async predict(features) {
        const input = tf.tensor2d([features]);
        
        try {
            if (this.config.modelType === 'autoencoder') {
                // Reconstruction error as anomaly score
                const reconstructed = this.model.predict(input);
                const error = tf.losses.meanSquaredError(input, reconstructed);
                const score = await error.data();
                
                reconstructed.dispose();
                error.dispose();
                input.dispose();
                
                return score[0];
            } else if (this.config.modelType === 'isolation-forest') {
                const score = await this.isolationForestPredict(features);
                input.dispose();
                return score;
            } else {
                // One-class SVM
                const prediction = this.model.predict(input);
                const score = await prediction.data();
                prediction.dispose();
                input.dispose();
                
                return 1 - score[0]; // Invert for anomaly score
            }
        } catch (error) {
            input.dispose();
            throw error;
        }
    }

    async isolationForestPredict(features) {
        if (this.isolationTrees.length === 0) {
            return 0; // No trees built yet
        }
        
        let totalPathLength = 0;
        
        for (const tree of this.isolationTrees) {
            totalPathLength += this.getPathLength(features, tree, 0);
        }
        
        const avgPathLength = totalPathLength / this.isolationTrees.length;
        const c = this.getAveragePathLength(this.sampleSize);
        
        // Anomaly score
        return Math.pow(2, -avgPathLength / c);
    }

    getPathLength(features, node, currentDepth) {
        if (!node || !node.splitFeature || currentDepth > 10) {
            return currentDepth;
        }
        
        if (features[node.splitFeature] < node.splitValue) {
            return this.getPathLength(features, node.left, currentDepth + 1);
        } else {
            return this.getPathLength(features, node.right, currentDepth + 1);
        }
    }

    getAveragePathLength(n) {
        if (n <= 1) return 0;
        if (n === 2) return 1;
        
        const H = Math.log(n - 1) + 0.5772156649; // Euler's constant
        return 2 * H - (2 * (n - 1) / n);
    }

    addTrainingData(features, isAnomaly) {
        if (this.trainingData.length >= this.config.maxTrainingData) {
            this.trainingData.shift(); // Remove oldest
        }
        
        this.trainingData.push({
            features,
            isAnomaly,
            timestamp: Date.now()
        });
    }

    async train() {
        if (this.isTraining || this.trainingData.length < this.config.minTrainingData) {
            return;
        }
        
        this.isTraining = true;
        
        try {
            console.log('[AI Anomaly Detector] Starting training with', this.trainingData.length, 'samples');
            
            // Prepare training data
            const normalData = this.trainingData
                .filter(d => !d.isAnomaly)
                .map(d => d.features);
            
            if (normalData.length < 100) {
                console.log('[AI Anomaly Detector] Not enough normal data for training');
                return;
            }
            
            // Update scaler
            await this.updateScaler(normalData);
            
            // Train based on model type
            if (this.config.modelType === 'autoencoder') {
                await this.trainAutoencoder(normalData);
            } else if (this.config.modelType === 'isolation-forest') {
                await this.trainIsolationForest(normalData);
            } else {
                await this.trainOneClassSVM(normalData);
            }
            
            this.stats.modelUpdates++;
            this.stats.lastTraining = Date.now();
            
            console.log('[AI Anomaly Detector] Training completed');
            
            // Save model
            await this.saveModel();
            
        } catch (error) {
            console.error('[AI Anomaly Detector] Training error:', error);
        } finally {
            this.isTraining = false;
        }
    }

    async trainAutoencoder(data) {
        const xs = tf.tensor2d(data);
        const normalizedXs = xs.sub(this.scaler.mean).div(this.scaler.std.add(1e-8));
        
        // Train autoencoder to reconstruct normal data
        await this.model.fit(normalizedXs, normalizedXs, {
            batchSize: this.config.batchSize,
            epochs: this.config.epochs,
            validationSplit: 0.2,
            callbacks: {
                onEpochEnd: (epoch, logs) => {
                    if (epoch % 5 === 0) {
                        console.log(`[AI] Epoch ${epoch}: loss=${logs.loss.toFixed(4)}`);
                    }
                }
            }
        });
        
        xs.dispose();
        normalizedXs.dispose();
    }

    async trainIsolationForest(data) {
        this.isolationTrees = [];
        
        for (let i = 0; i < this.numTrees; i++) {
            const sample = this.randomSample(data, this.sampleSize);
            const tree = this.buildIsolationTree(sample, 0);
            this.isolationTrees.push(tree);
        }
    }

    buildIsolationTree(data, depth) {
        if (depth > 10 || data.length <= 1) {
            return null;
        }
        
        const featureIndex = Math.floor(Math.random() * this.config.inputDim);
        const values = data.map(d => d[featureIndex]);
        const min = Math.min(...values);
        const max = Math.max(...values);
        
        if (min === max) {
            return null;
        }
        
        const splitValue = min + Math.random() * (max - min);
        
        const leftData = data.filter(d => d[featureIndex] < splitValue);
        const rightData = data.filter(d => d[featureIndex] >= splitValue);
        
        return {
            splitFeature: featureIndex,
            splitValue,
            left: this.buildIsolationTree(leftData, depth + 1),
            right: this.buildIsolationTree(rightData, depth + 1)
        };
    }

    async trainOneClassSVM(data) {
        const xs = tf.tensor2d(data);
        const ys = tf.ones([data.length, 1]); // All normal data labeled as 1
        
        await this.model.fit(xs, ys, {
            batchSize: this.config.batchSize,
            epochs: this.config.epochs,
            validationSplit: 0.2
        });
        
        xs.dispose();
        ys.dispose();
    }

    async updateScaler(data) {
        const tensor = tf.tensor2d(data);
        
        this.scaler.mean = tensor.mean(0);
        this.scaler.std = tensor.sub(this.scaler.mean).square().mean(0).sqrt();
        
        tensor.dispose();
    }

    randomSample(array, size) {
        const sample = [];
        const indices = new Set();
        
        while (indices.size < Math.min(size, array.length)) {
            indices.add(Math.floor(Math.random() * array.length));
        }
        
        for (const index of indices) {
            sample.push(array[index]);
        }
        
        return sample;
    }

    getTopFeatures(features, normalizedFeatures) {
        const featureImportance = [];
        
        for (let i = 0; i < features.length; i++) {
            if (Math.abs(normalizedFeatures[i]) > 2) { // More than 2 std deviations
                featureImportance.push({
                    index: i,
                    name: this.config.features[i] || `feature_${i}`,
                    value: features[i],
                    normalized: normalizedFeatures[i]
                });
            }
        }
        
        return featureImportance.sort((a, b) => Math.abs(b.normalized) - Math.abs(a.normalized));
    }

    calculateConfidence(score) {
        // Sigmoid-based confidence
        const confidence = 1 / (1 + Math.exp(-10 * (score - this.config.threshold)));
        return Math.min(0.99, Math.max(0.01, confidence));
    }

    startTrainingSchedule() {
        this.trainingInterval = setInterval(() => {
            this.train();
        }, this.config.updateInterval);
    }

    async saveModel() {
        try {
            if (this.model && this.model.save) {
                await this.model.save('file://./models/anomaly-detector');
                console.log('[AI Anomaly Detector] Model saved');
            }
        } catch (error) {
            console.error('[AI Anomaly Detector] Save error:', error);
        }
    }

    async loadModel() {
        try {
            if (this.config.modelType === 'autoencoder') {
                const loaded = await tf.loadLayersModel('file://./models/anomaly-detector/model.json');
                if (loaded) {
                    this.model = loaded;
                    console.log('[AI Anomaly Detector] Model loaded');
                }
            }
        } catch (error) {
            console.log('[AI Anomaly Detector] No saved model found, using new model');
        }
    }

    getStats() {
        return {
            ...this.stats,
            modelType: this.config.modelType,
            threshold: this.config.threshold,
            trainingDataSize: this.trainingData.length,
            isTraining: this.isTraining,
            memoryUsage: tf.memory()
        };
    }

    async cleanup() {
        if (this.trainingInterval) {
            clearInterval(this.trainingInterval);
        }
        
        if (this.model) {
            this.model.dispose();
        }
        if (this.encoder) {
            this.encoder.dispose();
        }
        if (this.decoder) {
            this.decoder.dispose();
        }
        if (this.scaler) {
            if (this.scaler.mean) this.scaler.mean.dispose();
            if (this.scaler.std) this.scaler.std.dispose();
        }
        
        tf.engine().endScope();
        
        this.trainingData = [];
    }
}

module.exports = AnomalyDetector;