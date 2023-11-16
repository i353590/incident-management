package dcr._default_

__pol = x {
  x := input["$dcl"].policies
} else = x {
  dcl_utp  := input["$dcl"].principal2policies
  data_utp := data.principal2policies
  walk(data_utp,[dcl_utp, x])
} else = x {
  dcl_utp  := input["$dcl"].principal2policies
  data_utp := data.principal2policies
  x := []
} else = x {
  not input["$dcl"].principal2policies
  x := []
}

__polFilter = x {
  x := input["$dcl"].scopeFilter
} else = null

#
# <API>
#
ping = true

allow = x { x := data.cap.__grant(__pol, __polFilter) }
else = x { x := data.cap.__dclerror }
else = x { x := false }


allowAction = x {
  not input["$dcl"].resource
  x := allow
} else = x {
  i := input["$dcl"].resource
  x := {"$dclerror": -103, "message": "resource must not be set for allowAction"} 
}

allowPartial = x { x := data.cap.__grant(__pol, __polFilter) }

#
# </API>
#
