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

function reset() {

	$(this).fancybox({
		"type" : "html",
		"content" : "HEELLLLO!",
	});

}

function start_demo(data_source, tag) {

    //var w = d3.select(tag).style.width;
    //var h = d3.select(tag).style.height;
    var h = 245, w = 1080;
	//window.innerHeight - 150, w = window.innerWidth - 100;        
    var image_size = 100;
    var initted = false;
//    var force = d3.layout.force().gravity(0.5).linkDistance(250).charge(-100)
//            .linkStrength(5).size([w,h]);

    var force = d3.layout.force()
    .gravity(0.01)
	.friction(0.1)
    .distance(200).linkDistance(155)
    .charge(-100)
    .size([w, h])

    var nodes = force.nodes(),
        links = force.links();
	var services = new Array();
	var voip_links = new Array();
	var video_path_links = new Array();
	var video_path_nodes = new Array();
	var video_path_nodes_index = new Array();
	var voip_path_links = new Array();
	var voip_path_nodes = new Array();
	var voip_path_nodes_index = new Array();
	var voip_node = null;
	var voip_index = null;

    var svg = d3.select(tag).append("svg:svg")
        .attr("width", w)
        .attr("height", h);

    force.on("tick", function() {
        svg.selectAll("line.link")
            .attr("x1", function(d) { return d.source.x + image_sizes(d.source)/2; })
            .attr("y1", function(d) { return d.source.y + image_sizes(d.source)/2; })
            .attr("x2", function(d) { return d.target.x + image_sizes(d.target)/2; })
            .attr("y2", function(d) { return d.target.y + image_sizes(d.target)/2; });

        svg.selectAll("g.node")
        	.attr("transform", function(d) { return "translate(" + d.x + "," + d.y + ")"; });

    });

    d3.json(data_source, init);
    
    setInterval(function() {
        $.ajax({
            url: data_source,
            success: function(data) {
               update(data)
           },
            dataType: "json"
        });
     }, 1000);
   
    setTimeout("setTipsy(\'"+tag+"\')", 3000); 
 
    Array.prototype.diff = function(arr) {
        return this.filter(function(i) {
		for (var j = 0; j < arr.length ; j++) {
		   if (arr[j].id == i.id)
			return false;
		}
		console.log("Found a diff " + i.id);
		return true;
	});
    };
	Array.prototype.sdiff = function(arr) {
        return this.filter(function(i) {
		for (var j = 0; j < arr.length ; j++) {
		   if (arr[j] == i)
			return false;
		}
		console.log("Found a diff in service" + i);
		return true;
	});
    };

	Array.prototype.indexAt = function(item){
		var len = this.length;
		var i = 0;
		while( i < len ){
			if( this[i] === item ) return i;
			++i;
		}
		return -1;
	}


    function init(json) {

		json.services.forEach(function(item){
			console.log(item);
			services.push(item);
		});
		var i = 0;
        json.nodes.forEach(function(item) {
            //console.log(item);
			if( item.name == "phone"){
				/*if( services.indexAt("voip") != -1 ){
					console.log("only show phone node when voip is on");
					nodes.push(item);
				}*/
				voip_node = item;
				voip_index = i;
				//console.log("voip node: ");
				//console.log(voip_index);
				nodes.push(item);
			}else{
				if( item.group == 1){
					video_path_nodes.push(item);
					video_path_nodes_index.push(i);
				}else if(item.group == 2){
					voip_path_nodes.push(item);
					voip_path_nodes_index.push(i);
				}
				nodes.push(item);
			}
			i++;
        });
		//console.log(nodes);
        json.links.forEach(function(item) {
			console.log(item.source + "->" + item.target +", " + voip_node);
			console.log(item)
			if( item.source == voip_index || item.target == voip_index){
				/*if( services.indexAt("voip") != -1 ){
					console.log("only show link related to phone when voip is on");
					links.push(item);
				}*/
				voip_links.push(item);
				links.push(item);
			}else{
				if( video_path_nodes_index.indexAt(item.target) > -1 || video_path_nodes_index.indexAt(item.target) > -1){
					video_path_links.push(item);
				}else if( voip_path_nodes_index.indexAt(item.target) > -1 || voip_path_nodes_index.indexAt(item.target) > -1){
                    voip_path_links.push(item);
                }
				links.push(item);
			}
        });
		console.log(voip_links);
        initted = true;
        draw();
    }

    function update(json) {
		console.log("update is called");
        if (!initted) return;

        var changed = false;
	
/*		var n_adds = json.nodes.diff(nodes);
		var n_rems = nodes.diff(json.nodes);
		
		var l_adds = json.links.diff(links);
		var l_rems = links.diff(json.links); 

		for (var i = 0; i < n_rems.length ; i++) {
			for (var j = 0; j < nodes.length; j++) {
				if (nodes[j].id == n_rems[i].id) {
					nodes.splice(j,1);
					changed = true;
					break;
				}
			}
		}

		for (var i = 0; i < n_adds.length; i++) {
			nodes.push(n_adds[i]);
			changed = true;
		}

		for (var i = 0; i < l_rems.length ; i++) {
			for (var j = 0; j < links.length; j++) {
				if (links[j].id == l_rems[i].id) {
					links.splice(j,1);
					changed = true;
					break;
				}
			}
		}

		for (var i = 0; i < l_adds.length; i++) {
			links.push(l_adds[i]);
			changed = true;
		}
*/
		var s_adds = json.services.sdiff(services);
		var s_rems = services.sdiff(json.services);
		console.log(services);
		console.log(json.services);
		console.log(s_adds);
		console.log(s_rems);
		for(var i = 0; i < s_rems.length; i++){
				//remove service
			for (var j = 0; j < services.length; j++) {
				if(services[j] ==  s_rems[i]){
					services.splice(j, 1);
					changed = true;
					break;
				}
			}
			changed = true;
		}
		for (var i = 0; i < s_adds.length; i++) {
			services.push(s_adds[i]);
			changed = true;
		}
		/*
		for(var i = 0; i < s_rems.length; i++){
			console.log("removed service: " + s_rems[i]);
			if( s_rems[i] == "voip" ){
				console.log("voip_node: " + voip_node.name + voip_index);
				//remove associated nodes
				for (var j = 0; j < nodes.length; j++) {
					if(nodes[j].name == voip_node.name){
						//nodes.splice(j, 1);
						$(tag +' svg #'+nodes[j].name).attr("xlink:href", "../static/static/img/blank.jpg")
						changed = true;
						break;
					}
				}
				//remove associated links
				for (var j = 0; j < links.length; j++){
					console.log(links[j]);
					
					if(links[j].source.name == voip_node.name || links[j].target.name == voip_node.name ){
						$(tag +' svg #'+links[j].name).attr("stroke", "blank");
						changed = true;
					}
				}
			}
			//remove service
			for (var j = 0; j < services.length; j++) {
				if(services[j] ==  s_rems[i]){
					services.splice(j, 1);
					changed = true;
					break;
				}
			}
		}
		for (var i = 0; i < s_adds.length; i++) {
			console.log("added service: " + s_adds[i]);
			if( s_adds[i] == "voip"){
				//nodes.push(voip_node);
				$(tag +' svg #'+voip_node.name).attr("xlink:href", "../static/static/img/blank.jpg")
				for (var j = 0; j < voip_links.length; j++) {
					//links.push(voip_links[i]);
					$(tag +' svg #'+voip_links[j].name).attr("stroke", "blank")
				}
			}			
			services.push(s_adds[i]);
			changed = true;
		}
		for (var i=0; i< links.length; i++){
			 $(tag +' svg #'+links[i].name).attr("stroke", "black");
		}
		*/

        if (changed) 
            draw();
    }

	function animateVideoLink(){
		
	}

    function draw() {
    
      var link = svg.selectAll("line.link")
          .data(links);

      link.enter().insert("svg:line", "g.node")
          .attr("stroke","black")
          .attr("stroke-width",4)
          .attr("class", "link")
          .attr("id", function(d){return d.name;});

      link.exit().remove();

      var node = svg.selectAll("g.node")
          .data(nodes);
	  console.log(node)
      var nodeEnter = node.enter().append("svg:g")
          .attr("class", "node")
          .call(force.drag);

      nodeEnter.append("svg:image")
          .attr("xlink:href", function(d){ console.log(d.name); return image(d);})
          .attr("width", function(d){ return image_sizes(d) + "px";})
          .attr("height", function(d){ return image_sizes(d) + "px";})
          .attr("id", function(d){return d.name;});

	  nodeEnter.append("svg:text")
        .attr("class", "nodetext")
        .attr("dx", 12)
        .attr("dy", ".35em");
        //.text(function(d) { return d.name });


	  var n = nodes.length;
	  nodes.forEach(function(d, i) {
		if(d.group == 0){
		  if(d.name != "phone"){
			  d.y = h / 5 * 1 - image_sizes(d)/2;
		  }else{
			  d.y = h / 5 * 1 - image_sizes(d)/2 + 150; 
		  }
		  d.x = position_x(d, w);
		}else if(d.group == 1){
			d.y = h / 5 * 1 - 50;
			if(d.name == "videof1"){
				d.x = 30;
			}else{
				d.x = 800;
			}
		}else if(d.group == 2){
			d.y = h / 5 * 1 - image_sizes(d)/2 + 50;
			if(d.name == "voipf1"){
				d.x = 30;
			}else if(d.name == "voipf2"){
				d.x = 600;
			}else{
				d.y = h / 5 * 1 - image_sizes(d)/2 + 190;
				d.x = 800;
			}
		}
		d.fixed = true;
		// d.x = w / n * i;
	  });

      node.exit().remove();



		if( services.indexAt("voip") != -1 ){
			for(var j = 0; j < voip_path_links.length; j++){
				console.log(voip_path_links[j].name);
				$(tag +' svg #'+voip_path_links[j].name).attr("stroke", "green").attr("stroke-width",4);
				console.log("try to get voip line");
				console.log( $(tag +' svg #'+voip_path_links[j].name));
			}
			/*$(tag +' svg #phone').show();
			for (var j = 0; j < voip_links.length; j++) {
				$(tag +' svg #'+voip_links[j].name).attr("stroke", "black")
            }*/

		}else{
			for(var j = 0; j < voip_path_links.length; j++){
				console.log(voip_path_links[j].name);
				$(tag +' svg #'+voip_path_links[j].name).attr("stroke", "blank");
				console.log("try to get voip line");
				console.log( $(tag +' svg #'+voip_path_links[j].name));
			}
			console.log("trying to hide the phone when voip is not enabled");
			/*$(tag +' svg #phone').hide();
			for (var j = 0; j < voip_links.length; j++) {
				$(tag +' svg #'+voip_links[j].name).attr("stroke", "blank")
            }*/
			//$(tag +' svg #'+voip_link.name).hide();
		}
		if( services.indexAt("video") != -1 ){
			for(var j = 0; j < video_path_links.length; j++){
				console.log(video_path_links[j].name);
				$(tag +' svg #'+video_path_links[j].name).attr("stroke", "blue").attr("stroke-width",8);
				//$(tag +' svg #'+video_path_links[j].name).attr("stroke-width",8)
				console.log("try to get video line");
				console.log( $(tag +' svg #'+video_path_links[j].name));
			}
		}else{
			for(var j = 0; j < video_path_links.length; j++){
				console.log(video_path_links[j].name);
				$(tag +' svg #'+video_path_links[j].name).attr("stroke", "blank");
				console.log("try to get video line");
				console.log( $(tag +' svg #'+video_path_links[j].name));
			}
		}





      force.start();
    }

}
function position_x(d, w){
	if(d.name == "switch"){
		return 200 + image_sizes(d)/2;
	}else if(d.name == "ap"){
		return 500 + image_sizes(d)/2;
	}else if(d.name == "client"){
		return 700 + image_sizes(d);
	}else if(d.name == "cloud"){
		return 30;//image_sizes(d)/2;
	}else if(d.name == "phone"){
		return 700 + image_sizes(d)/2;
	}

}
function position_y(d, h){
	if(d.name == "switch"){
		return 1*h/3;
	}else if(d.name == "ap"){
		return 2*h/3;
	}else if(d.name == "client"){
		return 3*h/3;
	}
}

function image_sizes(d){
	if(d.group == 0){
		if(d.name == "switch"){
			return 150;
		}else if(d.name == "ap"){
			return 80;
		}else if(d.name == "client"){
			return 100;
		}else if(d.name == "cloud"){
			return 200;
		}else if(d.name == "phone"){
			return 100;
		}
	}else{
		return 1;
	}

}


function image(d){
	if(d.group == 0){
		if(d.name == "switch"){
			return "../static/static/img/pronto.jpg";
		}else if(d.name == "ap"){
			return "../static/static/img/ap.jpg";
		}else if(d.name == "client"){
			return "../static/static/img/mac.jpg";
		}else if(d.name == "cloud"){
			return "../static/static/img/cloud.jpg";
		}else if(d.name == "phone"){
			return "../static/static/img/phone.jpg";
		}
	}else{
		return "../static/static/img/blank.jpg";
	}
}
