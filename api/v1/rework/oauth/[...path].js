import { createOAuthBroker } from '../../../../server/oauth-broker/index.js';

const broker = createOAuthBroker();

export const config = {
  runtime: 'nodejs',
};

export default async function handler(req, res) {
  const originalUrl = req.url || '';
  if (originalUrl.startsWith('/api/v1/rework/oauth')) {
    req.url = originalUrl.replace(/^\/api\/v1/, '');
  }

  const handled = await broker.handle(req, res);
  if (!handled && !res.writableEnded) {
    res.statusCode = 404;
    res.end('Not Found');
  }
}
