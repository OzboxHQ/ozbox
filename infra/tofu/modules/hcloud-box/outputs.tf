output "machine_id" {
  description = "Hetzner server id."
  value       = hcloud_server.box.id
}

output "work_volume_id" {
  description = "The persistent /work volume id."
  value       = hcloud_volume.work.id
}

output "machine_type" {
  description = "The server type actually used."
  value       = hcloud_server.box.server_type
}
