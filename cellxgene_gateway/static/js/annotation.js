// Enhanced annotation functionality
// Annotations only work with file itemsources at the moment. If they work with others in the future we may need to revisit this.

const new_annotation_callback = (() => {
    const suffix = `.csv`;
    return (e) => {
        e.preventDefault();
        const el = $(e.target);
        const href = el.attr('href');
        const base = prompt(`Name your annotations collection\nnote: the suffix "${suffix}" will be appended`);
        if (base !== null && base.length > 0) {
            if (/^[0-9a-zA-Z_]+$/.test(base)) {
                window.location = `${href}/${base}${suffix}`;
            } else {
                alert("Error: name must match ^[0-9a-zA-Z_]+$\nthat is, only numbers, letters and underscore are allowed")
            }
        }
        return false;
    }
})();

// Enhanced annotation selection functionality
const annotation_selection_handler = (() => {
    return {
        showAnnotationOptions: function(datasetElement) {
            const annotationSpans = datasetElement.find('.annotation-item');
            if (annotationSpans.length > 1) {
                // Create a modal or dropdown for annotation selection
                const options = annotationSpans.map(function() {
                    const link = $(this).find('a:first');
                    return {
                        name: link.text(),
                        url: link.attr('href')
                    };
                }).get();
                
                return this.createAnnotationModal(options);
            }
            return null;
        },
        
        createAnnotationModal: function(options) {
            // Create a simple modal for annotation selection
            const modal = $(`
                <div class="annotation-modal" style="
                    position: fixed; top: 50%; left: 50%; 
                    transform: translate(-50%, -50%);
                    background: white; padding: 20px; 
                    border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                    z-index: 1000; min-width: 300px;
                ">
                    <h5>Choose Annotation Set</h5>
                    <div class="annotation-options">
                        <div class="annotation-option" style="margin: 10px 0;">
                            <a href="${options[0].url.replace(/\/[^\/]*\/$/, '/')}" 
                               style="display: block; padding: 8px; text-decoration: none; 
                                      border: 1px solid #ddd; border-radius: 4px; margin: 5px 0;">
                                No annotations (original dataset)
                            </a>
                        </div>
                        ${options.map(opt => `
                            <div class="annotation-option" style="margin: 10px 0;">
                                <a href="${opt.url}" 
                                   style="display: block; padding: 8px; text-decoration: none; 
                                          border: 1px solid #ddd; border-radius: 4px; margin: 5px 0;">
                                    ${opt.name}
                                </a>
                            </div>
                        `).join('')}
                    </div>
                    <button class="close-modal" style="
                        float: right; margin-top: 10px; padding: 5px 10px;
                        border: none; background: #6c757d; color: white; border-radius: 4px;
                    ">Cancel</button>
                </div>
                <div class="modal-backdrop" style="
                    position: fixed; top: 0; left: 0; width: 100%; height: 100%;
                    background: rgba(0,0,0,0.5); z-index: 999;
                "></div>
            `);
            
            $('body').append(modal);
            
            // Close modal handlers
            modal.find('.close-modal, .modal-backdrop').click(function() {
                modal.remove();
            });
            
            return modal;
        }
    };
})();

// Initialize enhanced functionality when page loads
$(document).ready(function() {
    // Handle new annotation creation
    $("a.new").click(new_annotation_callback);
    
    // Add styling for download links
    $('<style>')
        .prop('type', 'text/css')
        .html(`
            .annotation-item {
                margin-right: 8px;
                white-space: nowrap;
            }
            .download-link {
                color: #007bff;
                text-decoration: none;
                margin-left: 4px;
                font-size: 0.9em;
            }
            .download-link:hover {
                color: #0056b3;
                text-decoration: none;
            }
            .annotation-options a:hover {
                background-color: #f8f9fa !important;
            }
        `)
        .appendTo('head');
    
    // Enhanced dataset link handling for annotation selection
    $('li').each(function() {
        const listItem = $(this);
        const datasetLink = listItem.find('> a').first();
        const annotationItems = listItem.find('.annotation-item');
        
        if (annotationItems.length > 1) {
            // Add a special indicator that multiple annotations are available
            datasetLink.after(' <span style="color: #28a745; font-size: 0.8em;">[Multiple annotations available]</span>');
            
            // Add click handler to show annotation options
            datasetLink.click(function(e) {
                e.preventDefault();
                annotation_selection_handler.showAnnotationOptions(listItem);
            });
        }
    });
});

