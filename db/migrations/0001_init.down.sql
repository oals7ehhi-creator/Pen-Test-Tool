-- 0001 init (down). Exact inverse of 0001_init.up.sql: drops everything the up created, restoring the prior
-- (empty) schema. No extension is dropped because the up creates none.
DROP TABLE IF EXISTS tenant;
