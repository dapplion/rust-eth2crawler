create table enrs (
  id bigint not null primary key UNIQUE,
  node_id binary(32) not null,
  seq bigint not null,
  ip binary(4) not null,
  tcp int,
  udp int,
  fork_digest binary(4) not null,
  next_fork_version binary(4) not null,
  next_fork_epoch binary(8) not null,
  attnets binary(8),
  syncnets binary(1),
  seen_timestamp integer not null,
  enr_txt text not null
)