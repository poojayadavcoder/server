import Visitor from "../models/Visitor.js";
import Ticket from "../models/Ticket.js";
import Alert from "../models/Alert.js";
import User from "../models/User.js";
import Society from "../models/Society.js";
import Staff from "../models/Staff.js";
import Admin from "../models/Admin.js";



/**
 * GET /operations/dashboard
 * Get today's arrivals and active tickets for a user.
 * Access: Authenticated User
 */
export const getDashboardData = async (req, res) => {
  try {
    if (req.userType === 'admin') {
      // Global stats for Admin
      const totalSocieties = await Society.countDocuments();
      const activeResidents = await User.countDocuments({ status: "active" });
      
      const startOfDay = new Date();
      startOfDay.setHours(0, 0, 0, 0);
      const endOfDay = new Date();
      endOfDay.setHours(23, 59, 59, 999);
      
      const visitorsToday = await Visitor.countDocuments({ 
        createdAt: { $gte: startOfDay, $lte: endOfDay } 
      });

      const openTickets = await Ticket.countDocuments({ 
        status: { $in: ["open", "assigned", "in progress"] } 
      });

      return res.json({
        totalSocieties,
        activeResidents,
        visitorsToday: visitorsToday || 0,
        openTickets: openTickets || 0,
        role: 'admin'
      });
    }

    const userId = req.user.id;
    const societyId = req.user.societyId;

    // 1. Get Today's Arrivals
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);
    const endOfDay = new Date();
    endOfDay.setHours(23, 59, 59, 999);

    const arrivals = await Visitor.find({
      hostUserId: userId,
      societyId: societyId,
      createdAt: { $gte: startOfDay, $lte: endOfDay },
      status: "approved"
    }).limit(2);

    // 2. Get Active (Open) Tickets
    const activeTickets = await Ticket.find({
      "raisedBy.id": userId,
      societyId: societyId,
      status: { $in: ["open", "assigned"] }
    }).sort({ createdAt: -1 }).limit(1);

    res.json({
      arrivals,
      activeTicket: activeTickets[0] || null
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};


/**
 * POST /operations/visitors/invite
 * Create a pre-approved guest invitation with a pass code.
 * Access: Authenticated User
 */
export const inviteGuest = async (req, res) => {
  try {
    const { type, fName, vehicleNumber, guestCount, expectedDate, timeWindow } = req.body;
    const userId = req.user.id;
    const societyId = req.user.societyId;
    
    if (!type || !fName) {
      return res.status(400).json({ message: "Guest type and name are required" });
    }
    
    // Generate a simple 4-digit pass code to match UI design
    const passCode = Math.floor(1000 + Math.random() * 9000).toString();

    const visitor = new Visitor({
      societyId,
      type,
      fName,
      vehicleNumber,
      guestCount: guestCount || 1,
      hostUserId: userId,
      status: "approved",
      passCode,
      expectedAt: expectedDate ? new Date(expectedDate) : new Date(),
      visitorPurpose: `Invitation: ${timeWindow || 'N/A'}`,
      flat: req.user.profile?.flat || null,
      block: req.user.profile?.tower || null
    });


    await visitor.save();

    res.status(201).json({
      message: "Invitation generated successfully",
      passCode,
      visitorId: visitor._id
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * POST /operations/tickets
 * Create a new support ticket.
 * Access: Authenticated User
 */
export const createTicket = async (req, res) => {
  try {
    const { type, description, priority, subType, attachments } = req.body;
    const userId = req.user.id;
    const societyId = req.user.societyId;
    
    if (!type || !description) {
      return res.status(400).json({ message: "Category and description are required" });
    }

    // Generate a simple 4-digit ticket suffix for display
    const ticketSuffix = Math.floor(1000 + Math.random() * 9000);
    const customTicketId = `#HD${ticketSuffix}`;

    const ticket = new Ticket({
      societyId,
      raisedBy: { id: userId, type: req.user.type || req.userType || "user" },
      type,
      subType: subType || null,
      description,
      priority: priority || "medium",
      attachments: attachments || [],
      status: "open"
    });

    await ticket.save();

    res.status(201).json({
      message: "Ticket created successfully",
      ticketId: ticket._id,
      customTicketId: customTicketId // For UI display like #HD6534
    });

    // In production, trigger notification to support staff here

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * GET /operations/tickets/user
 * Fetch all tickets raised by the current user.
 * Access: Authenticated User
 */
export const getUserTickets = async (req, res) => {
  try {
    const userId = req.user.id;
    const societyId = req.user.societyId;
    const { status } = req.query;

    let statusFilter = {};

    if (status === 'open' || status === 'active') {
      statusFilter = { status: { $in: ["open", "assigned", "in progress", "pending"] } };
    } else if (status === 'resolved' || status === 'closed') {
      statusFilter = { status: { $in: ["resolved", "closed"] } };
    }

    const tickets = await Ticket.find({
      "raisedBy.id": userId,
      societyId: societyId,
      ...statusFilter
    }).sort({ createdAt: -1 });

    res.json(tickets);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * POST /operations/alerts/sos
 * Raise an SOS emergency alert.
 * Access: Authenticated User
 */
export const sendSOS = async (req, res) => {
  try {
    const userId = req.user.id;
    const societyId = req.user.societyId;
    const { type, location } = req.body;

    const userName = req.user.name || "Resident";
    const userFlat = req.user.flat || "N/A";

    const alert = new Alert({
      societyId,
      raisedBy: { 
        id: userId, 
        name: userName, 
        flat: userFlat 
      },
      type: type || "sos",
      location: location || "Flat",
      status: "active"
    });

    await alert.save();
    console.log(`[SOS ALERT] User ${userName} in ${userFlat} raised an SOS!`);

    // --- NOTIFICATION LOGIC ---
    try {
      const allGuards = await Staff.find({
        societyId,
        role: "guard",
        status: "active",
        notificationToken: { $exists: true, $ne: "" }
      });

      const allAdmins = await Admin.find({
        notificationToken: { $exists: true, $ne: "" }
        // Note: Admin lookup might need societyId filter depending on multi-tenancy model
      });

      const notificationTokens = [
        ...allGuards.map(g => g.notificationToken),
        ...allAdmins.map(a => a.notificationToken)
      ];

      const title = type === 'assistance' ? "Assistance Requested" : "🚨 EMERGENCY SOS 🚨";
      const body = `${userName} from ${userFlat} needs ${type === 'assistance' ? 'assistance' : 'emergency help'}!`;

      for (const token of notificationTokens) {
        triggerPushNotification(
          token,
          title,
          body,
          {
            alertId: alert._id,
            type: "SOS_ALERT",
            userName,
            userFlat,
            location: alert.location,
            sosType: alert.type
          },
          null, // No specific user target (broadcast to all staff)
          societyId
        );
      }
    } catch (notifyErr) {
      console.error("[SOS NOTIFY] Critical failure sending notifications:", notifyErr.message);
    }
    // --- END NOTIFICATION LOGIC ---

    res.status(201).json({
      message: "SOS Alert sent to security",
      alertId: alert._id
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * GET /operations/tickets/:id
 * Get details of a specific ticket.
 * Access: Authenticated User
 */

/**
 * GET /operations/tickets/society
 * Get all tickets for the society (Admin/Staff view).
 * Access: Authenticated Staff/Admin
 */
export const getAllSocietyTickets = async (req, res) => {
  try {
    const { status, type, priority, societyId } = req.query;
    const userType = req.userType; // 'admin', 'staff', or 'user'

    let filter = {};

    // If user is admin, allow cross-society access
    if (userType === 'admin') {
      // Admin can filter by societyId if provided, otherwise see all
      if (societyId && societyId !== 'all') {
        filter.societyId = societyId;
      }
    } else {
      // Staff and regular users are restricted to their own society
      filter.societyId = req.user.societyId;
    }

    if (status && status !== 'all') filter.status = status;
    if (type && type !== 'all') filter.type = type;
    if (priority && priority !== 'all') filter.priority = priority;

    const tickets = await Ticket.find(filter)
      .sort({ createdAt: -1 });

    // Manually fetch user details and society details
    const ticketsWithDetails = await Promise.all(tickets.map(async (ticket) => {
      const ticketObj = ticket.toObject();
      
      // Fetch user details from auth service
      if (ticketObj.raisedBy?.id) {
        try {
          const user = await User.findOne({ _id: ticketObj.raisedBy.id });
          if (user) {
            ticketObj.raisedBy.id = {
              _id: user._id,
              displayName: user.displayName,
              flat: user.flat || user.profile?.flat || null,
              tower: user.tower || user.profile?.tower || null,
              mobile: user.mobile
            };
          }
        } catch (err) {
          console.error(`Failed to fetch user ${ticketObj.raisedBy.id}:`, err.message);
        }
      }

      // Fetch society details
      if (ticketObj.societyId) {
        try {
          const society = await Society.findOne({ _id: ticketObj.societyId })
            .select('name');
          if (society) {
            ticketObj.societyId = society;
          }
        } catch (err) {
          console.error(`Failed to fetch society ${ticketObj.societyId}:`, err.message);
        }
      }

      return ticketObj;
    }));

    res.json(ticketsWithDetails);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

export const getTicketById = async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;
    const societyId = req.user.societyId;

    const ticket = await Ticket.findOne({
      _id: id,
      societyId: societyId
    });

    if (!ticket) {
      return res.status(404).json({ message: "Ticket not found" });
    }

    res.json(ticket);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};


/**
 * PATCH /operations/tickets/:id/status
 * Update ticket status.
 * Access: Authenticated User
 */
export const updateTicketStatus = async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    const userId = req.user.id;
    const societyId = req.user.societyId;

    const validStatuses = ["open", "assigned", "in progress", "resolved", "closed", "pending"];
    if (!validStatuses.includes(status)) {
        return res.status(400).json({ message: "Invalid status" });
    }

    const updateData = { status };
    if (status === 'resolved' || status === 'closed') {
        updateData["resolution"] = {
            resolvedAt: new Date(),
            notes: "Closed by user" // Default note or handle if frontend sends it
        };
    }

    const ticket = await Ticket.findOneAndUpdate(
      { _id: id, societyId: societyId },
      { $set: updateData },
      { new: true }
    );

    if (!ticket) {
      return res.status(404).json({ message: "Ticket not found" });
    }

    res.json(ticket);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};



/**
 * GET /operations/visitors/society
 * Fetch all visitors for the entire society (Guard View).
 * Access: Authenticated Staff/Guard
 */
export const getSocietyVisitors = async (req, res) => {
  try {
    const societyId = req.user.societyId;
    
    // RBAC: Ideally check if req.user.type === 'staff'
    
    const visitors = await Visitor.find({
      societyId: societyId
    }).sort({ createdAt: -1 });

    if (visitors.length > 0) {
        console.log("[getSocietyVisitors] First visitor raw snapshot:", {
            id: visitors[0]._id,
            fName: visitors[0].fName,
            flat: visitors[0].flat,
            block: visitors[0].block,
            hasFlatField: Object.prototype.hasOwnProperty.call(visitors[0].toObject(), 'flat')
        });
    }

    res.json(visitors);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * GET /operations/visitors
 * Fetch all visitors (Admin View).
 * Supports filtering by societyId.
 */
/**
 * GET /operations/visitors
 * Fetch all visitors (Admin View).
 * Supports filtering by societyId and pagination.
 */
export const getAllVisitors = async (req, res) => {
  try {
    const { societyId, page = 1, limit = 10 } = req.query;
    const filter = {};

    if (societyId && societyId !== 'all') {
      filter.societyId = societyId;
    }

    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);
    const skip = (pageNum - 1) * limitNum;

    const total = await Visitor.countDocuments(filter);
    const visitors = await Visitor.find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limitNum);

    res.json({
      visitors,
      total,
      page: pageNum,
      pages: Math.ceil(total / limitNum)
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * PATCH /operations/visitors/:id/entry
 * Mark visitor entry time.
 * Access: Authenticated Staff/Guard
 */
export const markVisitorEntry = async (req, res) => {
  try {
    const { id } = req.params;
    const societyId = req.user.societyId;

    const visitor = await Visitor.findOne({ _id: id, societyId });
    if (!visitor) {
      return res.status(404).json({ message: "Visitor not found" });
    }

    visitor.entryTime = new Date();
    await visitor.save();

    res.json(visitor);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * PATCH /operations/visitors/:id/exit
 * Mark visitor exit time.
 * Access: Authenticated Staff/Guard
 */
export const markVisitorExit = async (req, res) => {
  try {
    const { id } = req.params;
    const societyId = req.user.societyId;

    const visitor = await Visitor.findOne({ _id: id, societyId });
    if (!visitor) {
      return res.status(404).json({ message: "Visitor not found" });
    }

    visitor.exitTime = new Date();
    await visitor.save();

    res.json(visitor);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * GET /operations/visitors/user
 * Fetch all visitors for the current user.
 * Access: Authenticated User
 */
export const getUserVisitors = async (req, res) => {
  try {
    const userId = req.user.id;
    const societyId = req.user.societyId;
    const visitors = await Visitor.find({
      hostUserId: userId,
      societyId: societyId
    }).sort({ createdAt: -1 });

    res.json(visitors);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

const findHostUser = async (societyId, block, flat) => {
    // Regex for block to allow flexible matching (e.g., "A" matches "A-BLOCK", "A Block", "BLOCK A")
    // Use case-insensitive and allow any characters before/after the block name
    const blockRegex = new RegExp(`^${block.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(\\b|\\s|-)`, 'i');
    
    return await User.findOne({
        societyId,
        "profile.flat": flat.trim(),
        "profile.tower": { $regex: blockRegex },
        status: "active"
    });
};

/**
 * GET /operations/visitors/check-resident
 * Find an active resident by flat and block.
 * Access: Authenticated Staff/Guard
 */
export const checkResident = async (req, res) => {
    try {
        const { block, flat } = req.query;
        
        // Defensive check for req.user
        if (!req.user) {
            console.error("[checkResident] No user object on request - middleware may have failed or not run");
            return res.status(401).json({ success: false, message: "Authentication failed" });
        }

        const societyId = req.user.societyId;
        console.log("[checkResident] Request context:", { block, flat, societyId, userType: req.userType });

        if (!block || !flat || !societyId) {
            return res.status(400).json({ success: false, message: "Missing required parameters (block, flat, or societyId)" });
        }

        const resident = await findHostUser(societyId, block, flat);

        if (!resident) {
            console.log("[checkResident] Resident not found for:", { block, flat });
            return res.status(404).json({
                success: false,
                message: "No active resident found for this flat"
            });
        }

        console.log("[checkResident] Found resident:", resident.displayName);

        res.status(200).json({
            success: true,
            data: {
                name: resident.displayName,
                userId: resident._id,
                mobile: resident.mobile
            }
        });
    } catch (error) {
        console.error("[checkResident] Error:", error.message);
        res.status(500).json({ success: false, message: error.message });
    }
};

/**
 * POST /operations/visitors/walk-in
 * Create a walk-in visitor entry by guard.
 * Access: Authenticated Staff/Guard
 */
export const createWalkInVisitor = async (req, res) => {
  try {
    const { 
        type, fName, mobile, vehicleNumber, flat, block, 
        company, purpose, photo, packageAtGate,
        cabCompany, cabTripType 
    } = req.body;
    const societyId = req.user.societyId;

    if (!type || !fName || !flat || !block) {
      return res.status(400).json({ message: "Type, Name, Flat and Block are required" });
    }

    // Find the resident user for this flat/block in this society
    const hostUser = await findHostUser(societyId, block, flat);

    if (!hostUser) {
        // Fallback or alert if no active resident found
        console.log(`[ALERT] No active resident found for ${block} - ${flat} in society ${societyId}`);
        // For demonstration, we'll allow it but you might want to force a resident check
        // return res.status(404).json({ message: "No active resident found for this flat." });
    }

    const visitor = new Visitor({
      societyId,
      type,
      fName,
      mobile: mobile || null,
      vehicleNumber: vehicleNumber || null,
      hostUserId: hostUser ? hostUser._id : "SYSTEM_UNASSIGNED",
      status: "approved",
      entryTime: new Date(),
      visitorPurpose: purpose || (type === 'cab' ? `${cabTripType}: ${cabCompany || 'Cab'}` : (company ? `Delivery: ${company}` : "Walk-in")),
      packageAtGate: packageAtGate || false,
      cabCompany: cabCompany || null,
      cabTripType: cabTripType || null,
      flat,
      block,
      // photo would typically be a media ID or URL after upload
    });

    await visitor.save();
    console.log("[createWalkInVisitor] Saved visitor with flat/block:", { id: visitor._id, flat: visitor.flat, block: visitor.block });

    // Trigger Notification if hostUser has a token
    if (hostUser && hostUser.notificationToken) {
        const title = type === 'delivery' ? 'Delivery Arrived' : 'Visitor Entered';
        const body = packageAtGate 
            ? `${fName} left a package at the gate for you.`
            : `${fName} has entered for ${block}-${flat}.`;

        triggerPushNotification(
            hostUser.notificationToken,
            title,
            body,
            { 
                visitorId: visitor._id, 
                type: "VISITOR_ENTRY", // Informational
                fName: fName,
                visitorType: type,
                block: block,
                flat: flat
            },
            hostUser._id,
            societyId
        );
    }

    res.status(201).json({
      message: "Visitor entry created successfully",
      visitor: {
        id: visitor._id,
        fName: visitor.fName,
        type: visitor.type,
        hostName: hostUser ? hostUser.displayName : "Unassigned",
        entryTime: visitor.entryTime
      }
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};


/**
 * GET /operations/visitors/check-guest
 * Check if a guest is pre-approved for a specific flat.
 * Access: Authenticated Staff/Guard
 */
export const checkPreApprovedGuest = async (req, res) => {
    try {
        const { flat, block } = req.query;
        const societyId = req.user.societyId;

        if (!flat || !block) {
            return res.status(400).json({ message: "Flat and Block are required" });
        }

        // 1. Find the resident user(s) for this flat
        const blockRegex = new RegExp(`^${block.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(\\b|\\s|-)`, 'i');
        const hostUsers = await User.find({
            societyId,
            "profile.flat": flat.trim(),
            "profile.tower": { $regex: blockRegex },
            status: "active"
        });

        if (hostUsers.length === 0) {
            return res.json({ found: false, message: "No active resident found for this flat" });
        }

        const hostUserIds = hostUsers.map(u => u._id);

        // 2. Find approved visitors for these hosts that haven't entered yet
        const guest = await Visitor.findOne({
            societyId,
            hostUserId: { $in: hostUserIds },
            type: "guest",
            status: "approved",
            entryTime: null
        }).sort({ createdAt: -1 });

        if (guest) {
            res.json({
                found: true,
                guest: {
                    id: guest._id,
                    name: guest.fName,
                    guestCount: guest.guestCount,
                    photo: `https://ui-avatars.com/api/?name=${encodeURIComponent(guest.fName)}&background=random&size=200`
                }
            });
        } else {
            res.json({ found: false });
        }

    } catch (err) {
        console.error("checkPreApprovedGuest error:", err);
        res.status(500).json({ error: err.message });
    }
};

const triggerPushNotification = async (token, title, body, data, userId, societyId) => {
    try {
        const INFRA_URL = process.env.INFRA_URL || "http://localhost:5003";
        await fetch(`${INFRA_URL}/notifications/push`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ token, title, body, data, userId, societyId })
        });
        console.log(`[Notification] Pushed to ${userId}`);
    } catch (error) {
        console.error("[Notification] Failed to trigger push:", error.message);
    }
};

/**
 * POST /operations/visitors/request-approval
 * Generic API to create a visitor entry with 'requested' status for walk-in.
 * Access: Authenticated Staff/Guard
 */
export const requestVisitorApproval = async (req, res) => {
    try {
        console.log("[requestVisitorApproval] Incoming request body:", req.body);
        const { 
            fName, visitorType, purpose, flat, block, 
            mobile, guestCount, vehicleNumber, 
            company, packageAtGate, photo,
            cabCompany, cabTripType
        } = req.body;
        const societyId = req.user.societyId;

        if (!societyId) {
            return res.status(400).json({ message: "Invalid token: missing societyId" });
        }

        if (!fName || !visitorType || !flat || !block) {
            return res.status(400).json({ message: "Name, Type, Flat and Block are required" });
        }

        const hostUser = await findHostUser(societyId, block, flat);

        const visitorData = {
            societyId,
            type: visitorType,
            fName,
            mobile: mobile || null,
            guestCount: guestCount || 1,
            vehicleNumber: vehicleNumber || null,
            hostUserId: hostUser ? hostUser._id : null,
            status: "requested",
            visitorPurpose: purpose || `Walk-in ${visitorType} Visit`,
            flat,
            block,
            company: company || null,
            packageAtGate: packageAtGate || false,
            photo: photo || null,
            cabCompany: cabCompany || null,
            cabTripType: cabTripType || null
        };

        const visitor = new Visitor(visitorData);
        console.log("[requestVisitorApproval] Visitor Object Structure:", JSON.stringify(visitor.toObject(), null, 2));
        console.log("[requestVisitorApproval] Pre-save document flat/block:", { flat: visitor.flat, block: visitor.block });
        await visitor.save();
        console.log("[requestVisitorApproval] Post-save document flat/block:", { flat: visitor.flat, block: visitor.block });

        // Trigger Notification if hostUser has a token
        if (hostUser && hostUser.notificationToken) {
            triggerPushNotification(
                hostUser.notificationToken,
                "New Visitor Request",
                `${fName} is at the gate for ${block}-${flat}. Do you approve?`,
                { 
                    visitorId: visitor._id, 
                    type: "VISITOR_APPROVAL",
                    fName: fName,
                    visitorType: visitorType,
                    block: block,
                    flat: flat
                },
                hostUser._id,
                societyId
            );
        }

        res.status(201).json({ 
            message: "Visitor approval requested", 
            visitorId: visitor._id,
            hostMobile: hostUser ? (hostUser.mobile || hostUser.profile?.alternateMobile || null) : null,
            status: visitor.status
        });

    } catch (error) {
        console.error("[requestVisitorApproval] ERROR:", error);
        res.status(500).json({ 
            message: "Failed to request approval",
            error: error.message 
        });
    }
};


/**
 * @deprecated Use requestVisitorApproval instead.
 * POST /operations/visitors/request-guest-approval
 */
export const requestGuestApproval = async (req, res) => {
    req.body.visitorType = "guest";
    return requestVisitorApproval(req, res);
};

/**
 * PATCH /operations/visitors/:id/status
 * Update visitor status (Approve/Deny).
 * Access: Resident (Host)
 */
export const approveVisitor = async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body; // 'approved' or 'denied'
        const userId = req.user.id;
        const societyId = req.user.societyId;

        if (!['approved', 'denied'].includes(status)) {
            return res.status(400).json({ message: "Invalid status. Use 'approved' or 'denied'." });
        }

        const visitor = await Visitor.findOne({ _id: id, societyId });
        if (!visitor) {
            return res.status(404).json({ message: "Visitor not found" });
        }

        // Verify that the person approving is the host
        if (visitor.hostUserId !== userId) {
            return res.status(403).json({ message: "You are not authorized to approve this visitor" });
        }

        visitor.status = status;
        if (status === 'approved') {
            visitor.entryTime = new Date(); // Auto mark entry on approval if desired, or let guard do it
        }
        await visitor.save();

        res.json({ message: `Visitor ${status} successfully`, visitor });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

/**
 * GET /operations/visitors/:id
 * Get details of a specific visitor (including status).
 * Access: Authenticated Staff/Guard
 */
export const getVisitorById = async (req, res) => {
    try {
        const { id } = req.params;
        const societyId = req.user.societyId;

        const visitor = await Visitor.findOne({ _id: id, societyId });
        if (!visitor) {
            return res.status(404).json({ message: "Visitor not found" });
        }

        // Attach host mobile if hostUserId exists
        let hostMobile = null;
        if (visitor.hostUserId && visitor.hostUserId !== "SYSTEM_UNASSIGNED") {
            const host = await User.findById(visitor.hostUserId);
            if (host) {
                hostMobile = host.mobile || host.profile?.alternateMobile || null;
            }
        }

        res.json({
            ...visitor.toObject(),
            hostMobile
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

/**
 * POST /operations/staff/entry
 * Mark entry for service personnel (Daily Help).
 */
export const staffEntry = async (req, res) => {
    try {
        if (!req.user || !req.user.societyId) {
            return res.status(401).json({ message: "Incomplete user profile or missing society context" });
        }
        const { servicePersonnelId, name, type } = req.body;
        const societyId = req.user.societyId;

        if (!servicePersonnelId || !name || !type) {
            return res.status(400).json({ message: "ServicePersonnelId, Name and Type are required" });
        }

        // Check if already inside
        const activeEntry = await Visitor.findOne({
            societyId,
            servicePersonnelId,
            exitTime: null,
            status: "approved"
        });

        if (activeEntry) {
            return res.status(409).json({ message: "Staff is already inside" });
        }

        const visitor = new Visitor({
            societyId,
            type, // maid, driver, etc.
            fName: name,
            servicePersonnelId,
            status: "approved",
            entryTime: new Date(),
            visitorPurpose: "Daily Service",
        });

        await visitor.save();

        res.status(201).json({
            message: "Staff entry marked successfully",
            visitorId: visitor._id,
            entryTime: visitor.entryTime
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

/**
 * POST /operations/staff/exit
 * Mark exit for service personnel.
 */
export const staffExit = async (req, res) => {
    try {
        if (!req.user || !req.user.societyId) {
            return res.status(401).json({ message: "Incomplete user profile or missing society context" });
        }
        const { servicePersonnelId } = req.body;
        const societyId = req.user.societyId;

        if (!servicePersonnelId) {
            return res.status(400).json({ message: "ServicePersonnelId is required" });
        }

        const activeEntry = await Visitor.findOne({
            societyId,
            servicePersonnelId,
            exitTime: null,
            status: "approved"
        });

        if (!activeEntry) {
            return res.status(404).json({ message: "Staff not currently inside" });
        }

        activeEntry.exitTime = new Date();
        await activeEntry.save();

        res.json({
            message: "Staff exit marked successfully",
            exitTime: activeEntry.exitTime
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

/**
 * GET /operations/staff/status
 * Get list of staff currently inside.
 */
export const getStaffStatus = async (req, res) => {
    try {
        if (!req.user || !req.user.societyId) {
            return res.status(401).json({ message: "Missing society context" });
        }
        const societyId = req.user.societyId;

        const activeStaff = await Visitor.find({
            societyId,
            servicePersonnelId: { $ne: null },
            exitTime: null,
            status: "approved"
        }).select("servicePersonnelId entryTime");

        // Return lookup map or list 
        const statusMap = activeStaff.reduce((acc, curr) => {
            acc[curr.servicePersonnelId] = {
                status: "IN",
                entryTime: curr.entryTime
            };
            return acc;
        }, {});

        res.json(statusMap);

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

/**
 * POST /operations/visitors/verify-code
 * Verify a guest's 4-digit pass code and mark entry.
 * Access: Authenticated Staff/Guard
 */
export const verifyPassCode = async (req, res) => {
    try {
        const { passCode } = req.body;
        const societyId = req.user.societyId;

        if (!passCode) {
            return res.status(400).json({ message: "Pass Code is required" });
        }

        // Find visitor with this code, society, and NOT yet entered
        const visitor = await Visitor.findOne({
            societyId,
            passCode,
            status: "approved",
            entryTime: null
        }).populate("hostUserId", "displayName profile.flat profile.tower");

        if (!visitor) {
            return res.status(404).json({ message: "Invalid or expired pass code." });
        }

        // Mark Entry Immediately
        visitor.entryTime = new Date();
        await visitor.save();

        // Trigger Notification to Host
        if (visitor.hostUserId && visitor.hostUserId.notificationToken) {
            triggerPushNotification(
                visitor.hostUserId.notificationToken,
                "Guest Arrived",
                `${visitor.fName} has entered the society.`,
                { 
                    visitorId: visitor._id, 
                    type: "VISITOR_ENTRY",
                    fName: visitor.fName,
                    visitorType: visitor.type,
                },
                visitor.hostUserId._id,
                societyId
            );
        }

        res.json({
            message: "Guest verified and entry marked.",
            visitor: {
                id: visitor._id,
                name: visitor.fName,
                type: visitor.type,
                host: visitor.hostUserId ? visitor.hostUserId.displayName : "Unknown",
                flat: visitor.hostUserId?.profile?.flat || "N/A"
            }
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};
