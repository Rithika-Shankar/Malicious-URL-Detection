$(document).ready(function() {
    $('#urlForm').submit(function(event) {
        event.preventDefault(); // Prevent the form from submitting via the browser

        var url = $('#urlInput').val(); // Get the URL input value

        // AJAX POST request to send the URL data to the backend
        $.ajax({
            type: 'POST',
            url: '/api/analyze',
            data: {url: url},
            success: function(response) {
                console.log(response); // Log the response to the console for debugging

                // Update the UI with the analysis results
                $('#prediction').text(response.prediction);
                $('#probability').text(response.probability);
                $('#explanation').text(response.explanation);

                // Update features list
                var featuresList = $('#features');
                featuresList.empty(); // Clear previous features

                $.each(response.features, function(key, value) {
                    var featureItem = $('<li>').text(key + ': ' + value);
                    featuresList.append(featureItem);
                });

                // Show the result container
                $('#resultContainer').show();
            },
            error: function(error) {
                console.error('Error:', error); // Log any errors to the console
            }
        });
    });
});
