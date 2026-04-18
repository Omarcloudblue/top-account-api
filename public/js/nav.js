/* ── Navegación global ── */
const DISCORD_URL = 'https://discord.gg/XXXXXXX'; // TODO: reemplazar con link real

document.addEventListener('DOMContentLoaded', () => {

  // Marcar link activo según la página actual
  const page = location.pathname.split('/').pop() || 'index.html';
  document.querySelectorAll('.nav-links a, .nav-mobile a').forEach(a => {
    const href = a.getAttribute('href')?.split('/').pop();
    if (href === page || (page === '' && href === 'index.html')) {
      a.classList.add('active');
    }
  });

  // Rellenar links de Discord
  document.querySelectorAll('[data-discord]').forEach(el => {
    el.href = DISCORD_URL;
  });

  // Hamburger toggle
  const burger = document.getElementById('navBurger');
  const mobile = document.getElementById('navMobile');
  if (burger && mobile) {
    burger.addEventListener('click', () => {
      burger.classList.toggle('open');
      mobile.classList.toggle('open');
    });
  }
});
