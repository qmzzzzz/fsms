const Sentry = require('@sentry/node');

let initialized = false;

function initSentry() {
  if (process.env.SENTRY_DSN) {
    Sentry.init({
      dsn: process.env.SENTRY_DSN,
      environment: process.env.NODE_ENV || 'development',
      tracesSampleRate: process.env.NODE_ENV === 'production' ? 0.1 : 1.0,
      // v7 起 AutoSessionTracking 不再是 Sentry.Integrations 的成员，改为 init 选项。
      // 旧写法 new Sentry.Integrations.AutoSessionTracking() 拿到的是 undefined，
      // 会在配置 SENTRY_DSN 时直接抛 TypeError，导致初始化失败。
      autoSessionTracking: true,
      integrations: [new Sentry.Integrations.Http({ tracing: true })],
    });
    initialized = true;
    return true;
  }
  return false;
}

/** 是否已初始化（供调用方在 captureException 前判断，避免未配置时的无效调用噪音） */
function isSentryInitialized() {
  return initialized;
}

function sentryRequestHandler() {
  return Sentry.Handlers.requestHandler();
}

function sentryTracingHandler() {
  return Sentry.Handlers.tracingHandler();
}

function sentryErrorHandler() {
  return Sentry.Handlers.errorHandler();
}

function captureException(error, context = {}) {
  Sentry.captureException(error, { extra: context });
}

module.exports = {
  initSentry,
  isSentryInitialized,
  sentryRequestHandler,
  sentryTracingHandler,
  sentryErrorHandler,
  captureException,
};
