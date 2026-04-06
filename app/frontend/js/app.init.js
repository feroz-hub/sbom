// js/app.init.js

$(async function () {
  // Simple tab navigation
  $(".tablink").on("click", function (e) {
    e.preventDefault();
    $(".tablink").removeClass("active");
    $(this).addClass("active");
    const target = $(this).data("target");
    $(".tab").removeClass("active");
    $(target).addClass("active");
    if (target === "#tab-home") HomeUI.refresh();
  });

  // Init modules
  await HomeUI.init();   // Load dashboard first
  ProjectsUI.init();
  await SbomsUI.init();
  AnalysisUI.init();

  // Force Home tab to open on app load
  $(".tablink").removeClass("active");
  $(".tab").removeClass("active");

  $(".tablink[data-target='#tab-home']").addClass("active");
  $("#tab-home").addClass("active");

  // Refresh Home dashboard
  HomeUI.refresh();
});
 