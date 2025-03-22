// Add this to your JavaScript (in settings.html or a separate .js file)
$(document).ready(function() {
    // Add "All" category button if it doesn't exist yet
    if ($('.category-pill[data-category="All"]').length === 0) {
        $('.category-pills-container').prepend(
            '<div class="badge rounded-pill text-bg-secondary category-pill active" data-category="All">All</div>'
        );
    }

    // Make category selection toggleable
    $('.category-pill').click(function() {
        const category = $(this).data('category');

        // If clicking on "All" or clicking the already active category
        if (category === 'All' || $(this).hasClass('active')) {
            // Show all cards
            $('[data-category]').show();
            // Set only "All" as active
            $('.category-pill').removeClass('active');
            $('.category-pill[data-category="All"]').addClass('active');
        } else {
            // Regular category filtering
            $('.category-pill').removeClass('active');
            $(this).addClass('active');

            $('[data-category]').each(function() {
                const cardCategories = $(this).data('category').split(' ');
                if (cardCategories.includes(category)) {
                    $(this).show();
                } else {
                    $(this).hide();
                }
            });
        }
    });
});