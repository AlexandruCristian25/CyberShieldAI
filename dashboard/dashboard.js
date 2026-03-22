document.addEventListener('DOMContentLoaded', () => {
    const roleElement = document.querySelector('div[role]');
    const actionsContainer = document.querySelector('section > div') || document.createElement('div');
    const footerElement = document.querySelector('footer');
  
    // Simulare date - în realitate, acestea ar veni de la server prin API sau template rendering
    const userData = {
      role: "Admin",
      actions: ["scan files", "view logs", "manage users", "backup data"],
    };
  
    const currentYear = new Date().getFullYear();
  
    // Setăm rolul
    if (roleElement) {
      roleElement.textContent = `Role: ${userData.role}`;
    }
  
    // Setăm acțiunile
    if (userData.actions && userData.actions.length > 0) {
      actionsContainer.innerHTML = ''; // Curățăm dacă există ceva
  
      const grid = document.createElement('div');
      grid.className = "grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-6";
  
      userData.actions.forEach(action => {
        const button = document.createElement('button');
        button.title = `Perform ${action}`;
        button.className = "bg-blue-600 hover:bg-blue-700 focus:ring-4 focus:ring-blue-400/50 py-3 px-5 rounded-xl font-semibold transition text-lg w-full";
        button.textContent = action.charAt(0).toUpperCase() + action.slice(1);
  
        button.addEventListener('click', () => {
          handleAction(action);
        });
  
        grid.appendChild(button);
      });
  
      actionsContainer.appendChild(grid);
    } else {
      actionsContainer.innerHTML = `
        <div class="text-center text-gray-400 py-12">
          <p class="text-lg">No actions available for this role yet.</p>
        </div>
      `;
    }
  
    // Setăm anul curent
    if (footerElement) {
      footerElement.innerHTML = `© ${currentYear} CyberShield AI. All rights reserved.`;
    }
  });
  
  // Funcție de manipulare click pe acțiuni
  function handleAction(action) {
    alert(`Action triggered: ${action}`);
    // Aici poți integra ulterior redirect sau apel API pentru acțiune reală
  }
  