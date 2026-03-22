document.addEventListener('DOMContentLoaded', () => {
    console.log('Admin Panel Ready 🚀');
  
    const grantForm = document.querySelector('form[action="/admin/grant"]');
    const revokeForm = document.querySelector('form[action="/admin/revoke"]');
  
    function validateForm(form) {
      const role = form.querySelector('input[name="role"]').value.trim();
      const action = form.querySelector('input[name="action"]').value.trim();
      const regex = /^[a-zA-Z0-9_\\-]{3,50}$/;
  
      if (!regex.test(role) || !regex.test(action)) {
        showToast('⚠️ Role și Action invalide!', 'error');
        return false;
      }
      return true;
    }
  
    function disableFormButton(form, message = 'Se procesează...') {
      const button = form.querySelector('button[type="submit"]');
      if (button) {
        button.disabled = true;
        button.innerText = message;
        button.classList.add('opacity-50', 'cursor-not-allowed');
      }
    }
  
    function showToast(message, type = 'success') {
      const toast = document.createElement('div');
      toast.className = `fixed top-5 right-5 p-4 rounded-lg shadow-lg z-50 toast ${
        type === 'success' ? 'toast-success' : 'toast-error'
      } animate-fadeIn`;
      toast.textContent = message;
      document.body.appendChild(toast);
  
      setTimeout(() => {
        toast.classList.add('animate-fadeOut');
        setTimeout(() => toast.remove(), 1000);
      }, 3000);
    }
  
    if (grantForm) {
      grantForm.addEventListener('submit', (e) => {
        if (!validateForm(grantForm)) {
          e.preventDefault();
          return;
        }
        disableFormButton(grantForm, '✅ Permisiune acordată!');
      });
    }
  
    if (revokeForm) {
      revokeForm.addEventListener('submit', (e) => {
        if (!validateForm(revokeForm)) {
          e.preventDefault();
          return;
        }
  
        const confirmAction = confirm('⚠️ Ești sigur că vrei să revoci această permisiune?');
        if (!confirmAction) {
          e.preventDefault();
          return;
        }
  
        disableFormButton(revokeForm, '✅ Permisiune revocată!');
      });
    }
  
    const messageBox = document.querySelector('div[class*="bg-green-700"], div[class*="bg-red-700"]');
    if (messageBox) {
      const isSuccess = messageBox.classList.contains('bg-green-700');
      showToast(messageBox.innerText.trim(), isSuccess ? 'success' : 'error');
      setTimeout(() => {
        messageBox.classList.add('opacity-0', 'transition-opacity', 'duration-1000');
      }, 3000);
    }
  });
  