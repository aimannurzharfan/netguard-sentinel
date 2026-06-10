// Built-in exposed-host sample, mirrors samples/host_exposed.json. Lets judges
// see a full triage without a live target or the demo container.
export const SAMPLE_SCAN = JSON.stringify(
  {
    host: "10.0.0.5",
    ports: [
      { port: 80, service: "Apache httpd", version: "2.4.49", banner: "Apache/2.4.49" },
      { port: 21, service: "vsftpd", version: "2.3.4", banner: "220 vsftpd 2.3.4" },
      { port: 22, service: "OpenSSH", version: "7.4", banner: "SSH-2.0-OpenSSH_7.4" },
      { port: 443, service: "OpenSSL", version: "1.0.1", banner: "" },
    ],
  },
  null,
  2
)
