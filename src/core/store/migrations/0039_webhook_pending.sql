CREATE INDEX webhook_deliveries_pending ON webhook_deliveries (webhook_id, next_at)
  WHERE state = 'pending';
