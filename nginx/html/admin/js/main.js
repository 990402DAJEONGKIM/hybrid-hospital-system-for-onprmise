document.addEventListener("DOMContentLoaded", function () {
  // Variables
  const sassHeader = document.querySelector(".sass-header");
  const sassTopBar = document.querySelector(".sass-top-bar");
  const sassMobileMenuBtn = document.getElementById("sassMobileMenuBtn");
  const sassMobileMenu = document.getElementById("sassMobileMenu");
  const sassMobileMenuClose = document.getElementById("sassMobileMenuClose");
  const sassOverlay = document.getElementById("sassOverlay");

  // Scroll event for header animation
  window.addEventListener("scroll", function () {
    if (window.scrollY > 50) {
      sassHeader.classList.add("sass-header-scrolled");
      sassTopBar.style.height = "0";
      sassTopBar.style.padding = "0";
      sassTopBar.style.overflow = "hidden";
    } else {
      sassHeader.classList.remove("sass-header-scrolled");
      sassTopBar.style.height = "auto";
      sassTopBar.style.padding = "8px 0";
    }
  });

  // Mobile menu toggle
  sassMobileMenuBtn.addEventListener("click", function () {
    sassMobileMenu.classList.add("sass-active");
    sassOverlay.classList.add("sass-active");
    document.body.style.overflow = "hidden";
  });

  // Close mobile menu
  function closeMobileMenu() {
    sassMobileMenu.classList.remove("sass-active");
    sassOverlay.classList.remove("sass-active");
    document.body.style.overflow = "auto";
  }

  sassMobileMenuClose.addEventListener("click", closeMobileMenu);
  sassOverlay.addEventListener("click", closeMobileMenu);

  // Dynamic announcement bar
  const sassAnnouncementContent = document.querySelector(
    ".sass-announcement-content"
  );
  const contentWidth = sassAnnouncementContent.offsetWidth;
  const viewportWidth = window.innerWidth;

  // Adjust animation duration based on content length
  const animationDuration = Math.max(20, (contentWidth / viewportWidth) * 15);
  sassAnnouncementContent.style.animationDuration = `${animationDuration}s`;

  // Resize event handler
  window.addEventListener("resize", function () {
    // Recalculate animation duration on window resize
    const contentWidth = sassAnnouncementContent.offsetWidth;
    const viewportWidth = window.innerWidth;
    const animationDuration = Math.max(20, (contentWidth / viewportWidth) * 15);
    sassAnnouncementContent.style.animationDuration = `${animationDuration}s`;
  });

  // Add active state to current page in navigation
  const currentLocation = window.location.href;
  const menuItems = document.querySelectorAll(".sass-nav-link");
  const mobileMenuItems = document.querySelectorAll(".sass-mobile-nav-link");

  menuItems.forEach((item) => {
    if (item.href === currentLocation) {
      item.classList.add("sass-nav-link-active");
    } else {
      item.classList.remove("sass-nav-link-active");
    }
  });

  mobileMenuItems.forEach((item) => {
    if (item.href === currentLocation) {
      item.style.color = "var(--primary)";
    }
  });
});
