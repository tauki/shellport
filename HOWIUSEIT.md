# How I use Shellport

I run Shellport on an always-on Raspberry Pi and use it from my phone or computer.

My setup has three parts:

- **Hosting:** I use Hub, my self-hosted app manager, to keep Shellport running and provide HTTPS access.
- **Networking:** Tailscale connects my devices over a private network.
- **Shells:** I use Shellport for terminals on the Pi and SSH access to other computers. A separate tmux service keeps local sessions running through Hub or Shellport updates, so I can continue from another device.

On my phone, I add Shellport to the Home Screen. At my desk, I open it in a browser.

You can use another service manager, HTTPS proxy or private network. Follow [the installation guide](INSTALL.md) to choose a setup for your own computer.
