/**
 * SecureVault — Particles Background
 * High-performance, responsive particle network animation with mouse interaction.
 */

(function () {
  const canvas = document.getElementById('particles-canvas');
  if (!canvas) return;

  const ctx = canvas.getContext('2d');
  let particles = [];
  let animationId = null;
  let width = 0;
  let height = 0;

  // Configuration
  const isMobile = window.innerWidth <= 768;
  const config = {
    particleCount: isMobile ? 35 : 75,
    maxDistance: 110,
    mouseRadius: 150,
    baseSpeed: 0.4,
    particleColor: 'rgba(167, 139, 250, 0.25)', // Primary accent secondary color
    linkColor: 'rgba(124, 92, 252, 0.08)',      // Connective line color
  };

  // Track mouse coordinates
  const mouse = {
    x: null,
    y: null,
  };

  window.addEventListener('mousemove', (e) => {
    mouse.x = e.clientX;
    mouse.y = e.clientY;
  });

  window.addEventListener('mouseleave', () => {
    mouse.x = null;
    mouse.y = null;
  });

  class Particle {
    constructor() {
      this.reset(true);
    }

    reset(initial = false) {
      this.size = Math.random() * 2.5 + 1; // Size: 1px to 3.5px
      
      if (initial) {
        this.x = Math.random() * width;
        this.y = Math.random() * height;
      } else {
        // Spawn at edge if resetting off-screen
        if (Math.random() > 0.5) {
          this.x = Math.random() > 0.5 ? 0 : width;
          this.y = Math.random() * height;
        } else {
          this.x = Math.random() * width;
          this.y = Math.random() > 0.5 ? 0 : height;
        }
      }

      // Random speed in both dimensions
      const speedScale = (Math.random() * 0.6 + 0.4) * config.baseSpeed;
      const angle = Math.random() * Math.PI * 2;
      this.vx = Math.cos(angle) * speedScale;
      this.vy = Math.sin(angle) * speedScale;
      
      this.alpha = Math.random() * 0.5 + 0.2; // Opacity
    }

    update() {
      // Natural movement
      this.x += this.vx;
      this.y += this.vy;

      // Mouse repulsion
      if (mouse.x !== null && mouse.y !== null) {
        const dx = this.x - mouse.x;
        const dy = this.y - mouse.y;
        const distance = Math.hypot(dx, dy);

        if (distance < config.mouseRadius) {
          const force = (config.mouseRadius - distance) / config.mouseRadius;
          const angle = Math.atan2(dy, dx);
          
          // Gently push particle away
          this.x += Math.cos(angle) * force * 1.2;
          this.y += Math.sin(angle) * force * 1.2;
        }
      }

      // Screen wrapping
      if (this.x < 0) this.x = width;
      else if (this.x > width) this.x = 0;
      
      if (this.y < 0) this.y = height;
      else if (this.y > height) this.y = 0;
    }

    draw() {
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(167, 139, 250, ${this.alpha})`;
      ctx.fill();
    }
  }

  function resize() {
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = width;
    canvas.height = height;

    // Readjust count on resize
    const count = window.innerWidth <= 768 ? 35 : 75;
    if (particles.length !== count) {
      particles = [];
      for (let i = 0; i < count; i++) {
        particles.push(new Particle());
      }
    }
  }

  function init() {
    resize();
    window.addEventListener('resize', resize);
    animate();
  }

  function animate() {
    ctx.clearRect(0, 0, width, height);

    // Update and draw particles
    for (let i = 0; i < particles.length; i++) {
      particles[i].update();
      particles[i].draw();
    }

    // Connect particles
    for (let i = 0; i < particles.length; i++) {
      const p1 = particles[i];

      // Connect to mouse
      if (mouse.x !== null && mouse.y !== null) {
        const dx = p1.x - mouse.x;
        const dy = p1.y - mouse.y;
        const dist = Math.hypot(dx, dy);

        if (dist < config.mouseRadius) {
          const alpha = (1 - dist / config.mouseRadius) * 0.12;
          ctx.beginPath();
          ctx.moveTo(p1.x, p1.y);
          ctx.lineTo(mouse.x, mouse.y);
          ctx.strokeStyle = `rgba(124, 92, 252, ${alpha})`;
          ctx.lineWidth = 0.8;
          ctx.stroke();
        }
      }

      // Connect to other particles
      for (let j = i + 1; j < particles.length; j++) {
        const p2 = particles[j];
        const dx = p1.x - p2.x;
        const dy = p1.y - p2.y;
        const dist = Math.hypot(dx, dy);

        if (dist < config.maxDistance) {
          const alpha = (1 - dist / config.maxDistance) * 0.15;
          ctx.beginPath();
          ctx.moveTo(p1.x, p1.y);
          ctx.lineTo(p2.x, p2.y);
          ctx.strokeStyle = `rgba(167, 139, 250, ${alpha})`;
          ctx.lineWidth = 0.6;
          ctx.stroke();
        }
      }
    }

    animationId = requestAnimationFrame(animate);
  }

  // Initialise
  init();
})();
