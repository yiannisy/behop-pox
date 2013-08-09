function setTipsy(tag) {
    $(tag + ' svg image').tipsy({ 
        //trigger: 'manual',
        gravity: $.fn.tipsy.autoNS,
        html: true, 
        fade: true,
        title: function(){
            return $(this).attr('id');
        }   
    });   
}

function update(json) {
    var default_stats = document.getElementById("default_stats");
    //var voip_stats = document.getElementById("voip_stats");
    var video_stats = document.getElementById("video_stats");

    default_stats.innerHTML = json.default_stats;
    //voip_stats.innerHTML = json.voip_stats;
    video_stats.innerHTML = json.video_stats;
}

function start_stats_demo(data_source, tag){
    setInterval(function() {
	$.ajax({
	    url: data_source,
	    success: function(data){
		update(data)
	    },
	    dataType: "json"
	});
    },2000);

    // setTimeout("setTipsy(\'"+tag+"\')", 3000);
}
